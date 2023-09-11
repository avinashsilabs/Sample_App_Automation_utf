import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    SocketOptions,
    Cipher
)
from utf.interfaces.wifi import WlanError
import string
import random
from utf.utils.iperf.iperf_utils import ping
import time
import re
import uuid
from typing import Dict
from threading import Thread
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)

def dut_server_accept(wifi_dut, sock):
    wifi_dut.interfaces.wifi.bsdSocketAccept(socket_id=sock)

def connect_to_server(client_socket, device_ip, logger, server_port=5001):
    time.sleep(5)
    logger.info(f"Connecting from remote device to DUT socket {(device_ip, server_port)}")
    client_socket.connect_client_tcp(device_ip, server_port)

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
            "ext_custom_features": Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "server_cert": "mosquitto-utf.silabs.com.cert.pem",
            "server_key": "mosquitto-utf.silabs.com.key.pem",
            "set_send_feature_frame": True,
        }
    )
]
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_server_testcase_TC19110(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_client, logger, sl_collections
):
    """
    SSL Server Socket functionality of DUT, while connecting from a remote SSL enabled client socket
    """
    try:
        capture_filename = "test_sdk_ssl_server_testcase_TC19110"
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True,
                                                                   mode='power_save_low_latency',
                                                                   ping_count=10, retry_count=1)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
                                      timeout=15)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1)
        # Connect from third party device to the socket opened in the DUT
        ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001)
        # DUT
        socket_id = wifi_dut.interfaces.wifi.bsdSocketAccept(socket_id=sock)
        # The api returns 100 bytes of random data
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        # DUT sends 100 bytes of data over ssl socket
        wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=socket_id, data=data_sent)
        # SSL client socket opened in third-party device receives the data
        data_receive = ssl_client.interfaces.ssl.data_recv(data_length)

        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        assert b"success" in result, "unable to close opened tcp socket"
        logger.info(f"Successfully closed socket_id:{socket_id}  in the DUT")
        # DUT closes the tcp socket
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        assert b"success" in result, "unable to close opened tcp socket"
        logger.info(f"Successfully closed socket_id:{sock}  in the DUT")
        assert data_sent == data_receive.decode(), "data length sent and received is not matching"

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
                                             ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.parametrize("cipher_list", [
    [Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA256, Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA256,
     Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA, Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA]])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_SSL_server_functionality_by_configuring_cipher_suite_in_combination_C113934(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_client, logger, cipher_list, sl_collections
):
    """
    SSL server functionality with the given cipher suites.
    TLS_RSA_WITH_AES_256_CBC_SHA256
    TLS_RSA_WITH_AES_128_CBC_SHA256
    TLS_RSA_WITH_AES_256_CBC_SHA
    TLS_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_AES_128_CCM_8
    TLS_RSA_WITH_AES_256_CCM_8
    TLS_RSA_WITH_AES_256_CBC_SHA256 + TLS_RSA_WITH_AES_128_CBC_SHA256
    """
    try:
        capture_filename = "test_sdk_SSL_server_functionality_by_configuring_cipher_suite_in_combination_C113934"
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True,
                                                                   mode='power_save_low_latency',
                                                                   ping_count=10, retry_count=1)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        for cipher in cipher_list:
            if cipher == Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA256:
                cipher_str = 'TLS_RSA_WITH_AES_256_CBC_SHA256'
            elif cipher == Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA256:
                cipher_str = 'TLS_RSA_WITH_AES_128_CBC_SHA256'
            elif cipher == Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA:
                cipher_str = 'TLS_RSA_WITH_AES_256_CBC_SHA'
            elif cipher == Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA:
                cipher_str = 'TLS_RSA_WITH_AES_128_CBC_SHA'
            wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)
            # The below api opens ssl server socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket(protocol=1)
            assert sock == 0, "Socket id received is wrong. expected is 0"
            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
                                          timeout=15)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1)
            # Connect from third party device to the socket opened in the DUT
            ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001)
            # DUT
            socket_id = wifi_dut.interfaces.wifi.bsdSocketAccept(socket_id=sock)
            # The api returns 100 bytes of random data
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            data_length = len(data_sent)
            # DUT sends 100 bytes of data over ssl socket
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=socket_id, data=data_sent)
            # SSL client socket opened in third-party device receives the data
            data_receive = ssl_client.interfaces.ssl.data_recv(data_length)
            # DUT closes the tcp socket
            result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
            assert b"success" in result, "unable to close opened tcp socket"
            # DUT closes the tcp socket
            result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            ssl_client.interfaces.ssl.stop_client()
            assert b"success" in result, "unable to close opened tcp socket"
            assert data_sent == data_receive.decode(), "data length sent and received is not matching"

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
                                             ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_server_1_0version_client_1_2_testcase_TC19115(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_client, logger, sl_collections
):
    """
        Open ssl server socket with tls version-1.0 and try to connect to it from client which supports only 1.2
        PASS if Client connection to DUT server fails with expected error code else FAIL
    """
    try:
        capture_filename = "test_sdk_ssl_server_1_0version_client_1_2_testcase_TC19115"
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True,
                                                                   mode='power_save_low_latency',
                                                                   ping_count=10, retry_count=1)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        # The below api opens ssl server socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE_VERSION_1_0)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                 SocketOptions.SSL_ENABLE)
        logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_0_ENABLE} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")
        # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_0_ENABLE,
                                                 SocketOptions.SSL_ENABLE)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
                                      timeout=15)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1)
        # Connect from third party device to the socket opened in the DUT
        ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001, version="ssl_1.2")
        with pytest.raises(WlanError) as exc_info:
            socket_id = wifi_dut.interfaces.wifi.bsdSocketAccept(socket_id=sock)
        assert exc_info.value.error_code == 0xFFFFFFFF, "DUT sent wrong error code, expected is 0xFFFFFFFF"
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.wlan_get_status()
        assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"
        logger.info(f"DUT sent error code->{exc_info.value.error_code} when third-party ssl client operating at version "
                    f"1.2 trying to connect to ssl server opened in DUT with version 1.0 which is expected")

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
                                             ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_server_no_server_cert_testcase_TC19111(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_client, logger, sl_collections
):
    """
        SSL server socket functionality of DUT when no server certificate present in the module.
        PASS if client connection to DUT fails with expected error code else FAIL
    """
    try:
        capture_filename = "test_sdk_ssl_server_no_server_cert_testcase_TC19111"
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True,
                                                                   mode='power_save_low_latency',
                                                                   ping_count=10, retry_count=1)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        wifi_dut.interfaces.wifi.load_certificate(RS9116CertificateType.SSLServerCertificate,
                                                  cert_index=0)
        wifi_dut.interfaces.wifi.load_certificate(RS9116CertificateType.SSLServerPrivateKey,
                                                  cert_index=0)

        # The below api opens ssl server socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket(protocol=1)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
                                      timeout=15)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1)
        # Connect from third party device to the socket opened in the DUT
        ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001)
        with pytest.raises(WlanError) as exc_info:
            socket_id = wifi_dut.interfaces.wifi.bsdSocketAccept(socket_id=sock)
        assert exc_info.value.error_code == 0xFFFFFFFF, "DUT sent wrong error code, expected is 0xFFFFFFFF"
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.wlan_get_status()
        assert exc_info.value.error_code == 0xD1, f"DUT sent wrong error code expected is 0xD1"

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
                                             ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_server_connect_non_ssl_client_testcase_TC19112(
        wifi_sniffer, wifi_access_point, wifi_dut, remote_socket_factory, logger, sl_collections
):
    """
        SSL server functionality of DUT when non ssl client connect to socket.
        PASS if client connection to DUT fails with expected error code else FAIL
    """
    try:
        capture_filename = "test_sdk_ssl_server_connect_non_ssl_client_testcase_TC19112"
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True,
                                                                   mode='power_save_low_latency',
                                                                   ping_count=10, retry_count=1)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        # The below api opens ssl server socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket(protocol=1)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
                                      timeout=15)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1)
        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        thread = Thread(target=connect_to_server, args=(client_socket, device_ip, logger, 5001), )
        thread.start()
        with pytest.raises(WlanError) as exc_info:
            socket_id = wifi_dut.interfaces.wifi.bsdSocketAccept(socket_id=sock)
        assert exc_info.value.error_code == 0xFFFFFFFF, "DUT sent wrong error code, expected is 0xFFFFFFFF"
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.wlan_get_status()
        assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"
        logger.info(f"DUT sent error code {exc_info.value.error_code} when third-party tcp client is connected to it,"
                    f"But not starting "
                    f"ssl-handshake which is expected")

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
                                             ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.MultipleSslVersionSupport | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "server_cert": "server-cert.pem",
        "server_key": "server-key.pem",
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
def test_wifi_sdk_ssl_server_1_2version_client_1_0_testcase_TC19116(
        wifi_sniffer, wifi_dut, wifi_access_point, openssl, logger, sl_collections):
    """
        Open ssl server socket with tls 1.2 and try to connect to it from client which supports only 1.0
        PASS if client connection to DUT fails with expected error code else FAIL
    """
    try:
        capture_filename = "test_sdk_ssl_server_1_2version_client_1_0_testcase_TC19116"
        ping_count = 10
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        # configure interface for the channel of the access point
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        # dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        # bt power save to be included
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_parms=[0, 4, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SO_SSL_V_1_2_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                 SocketOptions.SSL_ENABLE)

        logger.info(f"TLS VERSION USED BY DUT SERVER--->{SocketOptions.SO_SSL_V_1_2_ENABLE}")
        # # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_2_ENABLE,
                                                 SocketOptions.SSL_ENABLE)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
                                      timeout=15)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1)

        th_start = Thread(target=dut_server_accept, args=(wifi_dut, sock, logger))
        th_start.start()

        logger.info(f"Stating the open ssl client with tls version 1")
        openssl.interfaces.client.start(host=device_ip, port=5001, tls_version="-tls1")
        th_start.join(timeout=10)
        time.sleep(5)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.wlan_get_status()
        assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"

        openssl.interfaces.client.stop()
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)

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
                                                       capture_filename,
                                                       ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
        if len(ssl_pkt['tls']) > 0:
            for i in ssl_pkt['tls']:
                if re.search(".*Client Hello", i):
                    version = re.search("Version:.*", i).group(0)
                    logger.info(f"TLS VERSION USED BY CLIENT is--->{version}")
                    assert "TLS 1.0" in version, "TLS version mismatch, expected TLS VERSION 1.2 to be sent by DUT"
                    assert "Client Hello" in i, "Client Hello packet missed"
        else:
            logger.info(f"SSL packets are not found")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.MultipleSslVersionSupport | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "server_cert": "server-cert.pem",
        "server_key": "server-key.pem",
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
def test_wifi_sdk_ssl_server_1_0version_client_1_0_testcase_TC19113(
        wifi_sniffer, wifi_dut, wifi_access_point, openssl, logger, sl_collections):
    """
        Open ssl server socket in DUT with TLS version 1.0 and connect SSL client to the DUT
        PASS if client connection to DUT status is success else FAIL
    """
    try:
        capture_filename = "test_sdk_ssl_server_1_0version_client_1_0_testcase_TC19113"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        # configure interface for the channel of the access point
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        # bt power save to be included
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_parms=[0, 4, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SO_SSL_V_1_0_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                 SocketOptions.SSL_ENABLE)
        logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_0_ENABLE} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")
        # # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_0_ENABLE,
                                                 SocketOptions.SSL_ENABLE)

        logger.info(f"TLS VERSION USED BY DUT SERVER--->{SocketOptions.SO_SSL_V_1_0_ENABLE}")

        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
                                      timeout=15)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1)

        th_start = Thread(target=dut_server_accept, args=(wifi_dut, sock, logger))
        th_start.start()

        logger.info(f"Stating the open ssl client with tls version 1")
        openssl.interfaces.client.start(host=device_ip, port=5001, tls_version="-tls1")
        th_start.join(timeout=10)
        time.sleep(5)

        wifi_dut.interfaces.wifi.wlan_get_status()

        buffer_length = 200

        data = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
        )
        buff_len = len(data)
        logger.info(f"DATA sent from remote PC to dut {data}")
        openssl.interfaces.client.send_message(data)
        time.sleep(5)
        buffer_length, buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
        logger.info(f"Data received on dut {buffer}")
        assert data == buffer.decode(), "Date received on dut does not match the data sent from host"

        openssl.interfaces.client.stop()
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)

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
                                                       capture_filename,
                                                       ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
        if len(ssl_pkt['tls']) > 0:
            for i in ssl_pkt['tls']:
                if re.search(".*Client Hello", i):
                    version = re.search("Version:.*", i).group(0)
                    logger.info(f"TLS VERSION USED BY CLIENT is--->{version}")
                    assert "TLS 1.0" in version, "TLS version mismatch, expected TLS VERSION 1.2 to be sent by DUT"
                    assert "Client Hello" in i, "Client Hello packet missed"
        else:
            logger.info(f"SSL packets are not found")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.MultipleSslVersionSupport | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "server_cert": "server-cert.pem",
        "server_key": "server-key.pem",
        "set_send_feature_frame": True,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_tcp_retransmission_functionality_over_ssl_server_after_remote_terminate_event_C19126(wifi_dut,
                                                                                                  wifi_access_point,
                                                                                                  wifi_sniffer, openssl,sl_collections,
                                                                                                  logger):
    """
        TCP retransmission functionality over ssl server socket
        PASS if remote terminate event is received after closing the client socket else fail.
    """
    try:
        capture_filename = "test_sdk_tcp_retransmission_functionality_over_ssl_server_after_remote_terminate_event_C19126"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        # configure interface for the channel of the access point
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        #bt power save to be included
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_parms=[0, 4, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SO_SSL_V_1_2_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        TCP_MAX_RETRY = 10
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                 TCP_MAX_RETRY)

        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                 SocketOptions.SSL_ENABLE)
        logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_2_ENABLE} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_2_ENABLE,
                                                 SocketOptions.SSL_ENABLE)

        logger.info(f"TLS VERSION USED BY DUT SERVER--->{SocketOptions.SO_SSL_V_1_2_ENABLE}")

        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
                                      timeout=15)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1)

        th_start = Thread(target=dut_server_accept, args=(wifi_dut, sock, logger))
        th_start.start()

        logger.info(f"Stating the open ssl client with tls version 1")
        openssl.interfaces.client.start(host=device_ip, port=5001)
        th_start.join(timeout=10)
        time.sleep(5)

        wifi_dut.interfaces.wifi.wlan_get_status()

        buffer_length = 200

        data = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
        )
        buff_len = len(data)
        logger.info(f"DATA sent from remote PC to dut {data}")
        openssl.interfaces.client.send_message(data)
        time.sleep(5)
        buffer_length, buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=1)
        logger.info(f"Data received on dut {buffer}")
        assert data == buffer.decode(), "Date received on dut does not match the data sent from host"
        openssl.interfaces.client.stop()
        time.sleep(10)
        buffer_length, buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=1)

        since_time = 0
        events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
        for event in events:
            if event.event_type == RS9116AsyncEventType.TCP_REMOTE_TERMINATE:
                logger.info("Received TCP_REMOTE_TERMINATE event")
                logger.info(f"Received the Event Type {event.event_type}, Event data {event.event_data}")
                remote_terminate = event.event_data
                assert remote_terminate, f"unable to find remote terminate event"

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        wifi_dut.interfaces.wifi.leave()
        validation = True

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0))'
        packet_filter2 = f'((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1))'

        logger.info("association request packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find association request and association response packets'
        logger.info("association response packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find association request and association response packets'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)