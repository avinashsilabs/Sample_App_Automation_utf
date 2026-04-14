import pytest
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
    Si91xCryptoWrapMode,
    Si91xCryptoKeyType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)

from utf.interfaces.wifi import WlanError
import string
import random
from random import randint
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


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.SSL
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
        ],
    },
)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('TC19110')
def test_wifi_sdk_ssl_server_testcase_TC19110(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_client, logger, sl_collections,
        ssl_server
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
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0],
                                                                 associated=False, power_save=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        logger.info(f"Applying performance profile mode")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        port1 = ssl_server.interfaces.ssl.config['device_port1']

        # Open ssl server socket in remote device-Port1
        ssl_server.interfaces.ssl.start_server(
            port=port1
        )
        server_ip = ssl_server.interfaces.ssl.server_ip

        # Open SSL client socket in the DUT
        sock = wifi_dut.interfaces.wifi.async_sdk_socket(domain="AF_INET",
                                                         stream_type="SOCK_STREAM",
                                                         protocol="IPPROTO_TCP")
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(
            f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        time.sleep(2)
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                           timeout=15)
        time.sleep(2)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1,
                                                       timeout=15)
        buffer_length = 1370
        # RX throughput test: server sends, DUT receives
        socket_no = 1
        pkt_count = 10000
        duration = 60
        ssl_server.interfaces.ssl.send_data(socket_no, pkt_count, msg_length=buffer_length,
                                                 duration=duration)
        time.sleep(80)
        bytes_sent = ssl_server.interfaces.ssl.data_send_stats(socket_no)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock, no_of_pkts="pkt_count", ttl=30)
        logger.info(f"*** result of rx_stats in wifidut {result}")
        bytes_received = int(result)
        logger.info(f"bytes sent by remote peer -> {bytes_sent}")
        logger.info(f"bytes received on socket {sock} -> {bytes_received}")
        time.sleep(2)
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger.info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        time.sleep(5)
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
        ssl_server.interfaces.ssl.stop_server()
#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
#         "features": Si91xFeatureBitMap.Default,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
#         | Si91xTCPIPFeatureBitMap.SSL
#         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
#         | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
#         "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
#         | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
#         ],
#     },
# )
# @pytest.mark.parametrize("cipher_list", [
#     [Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA256, Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA256,
#      Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA, Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA]])
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# def test_wifi_sdk_SSL_server_functionality_by_configuring_cipher_suite_in_combination_C113934(
#         wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cipher_list, sl_collections,
#         sniffer_filter
# ):
#     """
#     SSL server functionality with the given cipher suites.
#     TLS_RSA_WITH_AES_256_CBC_SHA256
#     TLS_RSA_WITH_AES_128_CBC_SHA256
#     TLS_RSA_WITH_AES_256_CBC_SHA
#     TLS_RSA_WITH_AES_128_CBC_SHA
#     TLS_RSA_WITH_AES_128_CCM_8
#     TLS_RSA_WITH_AES_256_CCM_8
#     TLS_RSA_WITH_AES_256_CBC_SHA256 + TLS_RSA_WITH_AES_128_CBC_SHA256
#     """
#     try:
#         capture_filename = "test_sdk_ssl_server_testcase_TC113934"
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel
#         )
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#
#         port1 = ssl_server.interfaces.ssl.config['device_port1']
#         cipher_mask = Cipher(1)
#         for cipher in cipher_list:
#             cipher_mask |= cipher
#             logger.info(
#                 f"\n\n****************** Running SSL test when cipher suite selected is {cipher} ******************")
#         for count in range(1, 4):
#             logger.info(f"************************ Initiating test for iteration: '{count}' ************************")
#             result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                     retry_count=3, rejoin_params=[0, 4, 40, 0],
#                                                                     associated=False, power_save=False)
#             device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#             logger.info(f"Applying performance profile mode")
#             wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
#             wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
#                                                         psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
#
#             logger.info(
#                 f"\n\n****************** Running SSL test with cipher mask {cipher_mask} ******************")
#             wifi_dut.interfaces.wifi.set_ssl_cipher(cipher_list=cipher_mask)
#
#             # Open ssl server socket in remote device-Port1
#             ssl_server.interfaces.ssl.start_server(
#                 port=port1
#             )
#             server_ip = ssl_server.interfaces.ssl.server_ip
#
#             # Open SSL client socket in the DUT
#             sock = wifi_dut.interfaces.wifi.async_sdk_socket(domain="AF_INET",
#                                                              stream_type="SOCK_STREAM",
#                                                              protocol="IPPROTO_TCP")
#             assert sock == 0, "Socket id received is wrong. expected is 0"
#             logger.info(
#                 f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
#             logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
#             # Enable ssl option for socket opened
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
#             time.sleep(2)
#             local_port = randint(5001, 60000)
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
#                                           timeout=15)
#             time.sleep(2)
#             wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1,
#                                                       timeout=15)
#             buffer_length = 1370
#             # RX throughput test: server sends, DUT receives
#             socket_no = 1
#             pkt_count = 10000
#             duration = 60
#             ssl_server.interfaces.ssl.send_data(socket_no, pkt_count, msg_length=buffer_length,
#                                                 duration=duration)
#             time.sleep(80)
#             bytes_sent = ssl_server.interfaces.ssl.data_send_stats(socket_no)
#             result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock, no_of_pkts="pkt_count", ttl=30)
#             logger.info(f"*** result of rx_stats in wifidut {result}")
#             bytes_received = int(result)
#             logger.info(f"bytes sent by remote peer -> {bytes_sent}")
#             logger.info(f"bytes received on socket {sock} -> {bytes_received}")
#             assert bytes_received > 0, "No data received on DUT SSL socket"
#             time.sleep(2)
#             wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
#             logger.info("Successfully closed opened socket in the DUT")
#             ssl_server.interfaces.ssl.stop_server()
#             time.sleep(5)
#
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger.info("Stop Sniffer finally")
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#         decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#         logger.info(f"DECRYPTION KEY-->{decryption_key}")
#
#         sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
#                                             ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
#         wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
#         "features": Si91xFeatureBitMap.Default,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
#         | Si91xTCPIPFeatureBitMap.SSL
#         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
#         | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
#         "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
#         | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
#         ],
#     },
# )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# def test_wifi_sdk_ssl_server_1_0version_client_1_2_testcase_TC19115(
#         wifi_sniffer, wifi_access_point, wifi_dut, openssl, logger, sl_collections,
#         ssl_server
# ):
#     """
#         Open ssl server socket with tls version-1.0 and try to connect to it from client which supports only 1.2
#         PASS if Client connection to DUT server fails with expected error code else FAIL
#     """
#     try:
#         capture_filename = "test_sdk_ssl_server_testcase_TC19115"
#
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel
#         )
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_params=[0, 4, 40, 0],
#                                                                  associated=False, power_save=False)
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         logger.info(f"Applying performance profile mode")
#         wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
#         wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
#                                                       psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
#         # port1 = ssl_server.interfaces.ssl.config['device_port1']
#         #server_ip = ssl_server.interfaces.ssl.server_ip
#         port1 = ssl_server.interfaces.ssl.config['device_port1']
#         #openssl.interfaces.server.start(port=5001, tls_version="-tls1_2")
#         # Open ssl server socket in remote device-Port1
#         ssl_server.interfaces.ssl.start_server(
#             port=port1, version="ssl_1.2"
#         )
#         server_ip = ssl_server.interfaces.ssl.server_ip
#
#         sock = wifi_dut.interfaces.wifi.socket()
#         assert sock == 0, "Socket id received is wrong. expected is 0"
#         logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
#
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_0")
#         time.sleep(2)
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port1,
#                                       timeout=15)
#         error_code = None
#         try:
#             wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=5001)
#         except Exception as err:
#             error_match = re.search("status:(.*)", str(err))
#             if error_match:
#                 error_code = error_match.group()
#                 logger.info(f"error_code: {error_code}")
#         assert error_code, "DUT sent error code when trying to connect to ssl socket with open_ssl_v1_0 which is expected"
#         logger.info(f"DUT sent error code when trying to connect to ssl socket with open_ssl_v1_0 which is expected")
#
#         openssl.interfaces.server.stop()
#         wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
#
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger.info("Stop Sniffer finally")
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#         decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#         logger.info(f"DECRYPTION KEY-->{decryption_key}")
#
#         ssl_pkt = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"],
#                                                        capture_filename,
#                                                        ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
#         if len(ssl_pkt['tls']) > 0:
#             for i in ssl_pkt['tls']:
#                 if re.search(".*Client Hello", i):
#                     version = re.search("Version:.*", i).group(0)
#                     logger.info(f"TLS VERSION USED BY CLIENT is--->{version}")
#                     assert "TLS 1.0" in version, "TLS version mismatch, expected TLS VERSION 1.2 to be sent by DUT"
#                     assert "Client Hello" in i, "Client Hello packet missed"
#         else:
#             logger.info(f"SSL packets are not found")
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
#         wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
#         "features": Si91xFeatureBitMap.Default,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
#         | Si91xTCPIPFeatureBitMap.SSL
#         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
#         | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
#         "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
#         | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
#         ],
#     },
# )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# def test_wifi_sdk_ssl_server_no_server_cert_testcase_TC19111(
#         wifi_sniffer, wifi_access_point, wifi_dut, ssl_client, logger, sl_collections
# ):
#     """
#         SSL server socket functionality of DUT when no server certificate present in the module.
#         PASS if client connection to DUT fails with expected error code else FAIL
#     """
#     try:
#         capture_filename = "test_sdk_ssl_server_no_server_cert_testcase_TC19111"
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel
#         )
#         wifi_dut.interfaces.wifi.clear_certificate(Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
#                                                    Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START)
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_params=[0, 4, 40, 0],
#                                                                  associated=False, power_save=False)
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         logger.info(f"Applying performance profile mode")
#         wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
#         wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
#                                                       psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
#
#
#         # The below api opens ssl server socket in the DUT
#         sock = wifi_dut.interfaces.wifi.socket(protocol=1)
#         assert sock == 0, f"socket id received is wrong, expected is 0"
#         # Socket binds at (device_ip, 5001) in DUT
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
#                                       timeout=15)
#         wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1)
#         # Connect from third party device to the socket opened in the DUT
#         ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001)
#         with pytest.raises(WlanError) as exc_info:
#             socket_id = wifi_dut.interfaces.wifi.bsdSocketAccept(socket_id=sock)
#         assert exc_info.value.error_code == 0xFFFFFFFF, "DUT sent wrong error code, expected is 0xFFFFFFFF"
#         with pytest.raises(WlanError) as exc_info:
#             wifi_dut.interfaces.wifi.wlan_get_status()
#         assert exc_info.value.error_code == 0xD1, f"DUT sent wrong error code expected is 0xD1"
#
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger.info("Stop Sniffer finally")
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#         decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#         logger.info(f"DECRYPTION KEY-->{decryption_key}")
#
#         sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
#                                              ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
#         wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
#         "features": Si91xFeatureBitMap.Default,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
#         | Si91xTCPIPFeatureBitMap.SSL
#         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
#         | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
#         "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
#         | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
#         ],
#     },
# )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# def test_wifi_sdk_ssl_server_connect_non_ssl_client_testcase_TC19112(
#         wifi_sniffer, wifi_access_point, wifi_dut, remote_socket_factory, logger, sl_collections
# ):
#     """
#         SSL server functionality of DUT when non ssl client connect to socket.
#         PASS if client connection to DUT fails with expected error code else FAIL
#     """
#     try:
#         capture_filename = "test_sdk_ssl_server_connect_non_ssl_client_testcase_TC19112"
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel
#         )
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True,
#                                                                    mode='power_save_low_latency',
#                                                                    ping_count=10, retry_count=1)
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         # The below api opens ssl server socket in the DUT
#         sock = wifi_dut.interfaces.wifi.socket(protocol=1)
#         assert sock == 0, f"socket id received is wrong, expected is 0"
#         logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
#         # Socket binds at (device_ip, 5001) in DUT
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
#                                       timeout=15)
#         wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1)
#         client_socket = remote_socket_factory.interfaces.socket.create_socket()
#         thread = Thread(target=connect_to_server, args=(client_socket, device_ip, logger, 5001), )
#         thread.start()
#         with pytest.raises(WlanError) as exc_info:
#             socket_id = wifi_dut.interfaces.wifi.bsdSocketAccept(socket_id=sock)
#         assert exc_info.value.error_code == 0xFFFFFFFF, "DUT sent wrong error code, expected is 0xFFFFFFFF"
#         with pytest.raises(WlanError) as exc_info:
#             wifi_dut.interfaces.wifi.wlan_get_status()
#         assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"
#         logger.info(f"DUT sent error code {exc_info.value.error_code} when third-party tcp client is connected to it,"
#                     f"But not starting "
#                     f"ssl-handshake which is expected")
#
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger.info("Stop Sniffer finally")
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#         decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#         logger.info(f"DECRYPTION KEY-->{decryption_key}")
#
#         sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
#                                              ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
#
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
#         "features": Si91xFeatureBitMap.Default,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
#         | Si91xTCPIPFeatureBitMap.SSL
#         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
#         | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
#         "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
#         | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
#         ],
#     },
# )
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
#                              "clear_certs"])
# def test_wifi_sdk_ssl_server_1_2version_client_1_0_testcase_TC19116(
#         wifi_sniffer, wifi_dut, wifi_access_point, openssl, logger, sl_collections,
#         ssl_server
# ):
#     """
#         Open ssl server socket with tls 1.2 and try to connect to it from client which supports only 1.0
#         PASS if client connection to DUT fails with expected error code else FAIL
#     """
#     try:
#         capture_filename = "test_sdk_ssl_server_testcase_TC19115"
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel
#         )
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_params=[0, 4, 40, 0],
#                                                                  associated=False, power_save=False)
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         logger.info(f"Applying performance profile mode")
#         wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
#         wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
#                                                       psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
#         # port1 = ssl_server.interfaces.ssl.config['device_port1']
#         openssl.interfaces.server.start(port=5001, tls_version="-tls1")
#         # Open ssl server socket in remote device-Port1
#         # ssl_server.interfaces.ssl.start_server(
#         #     port=port1, tls_version="-tls1_2"
#         # )
#         server_ip = ssl_server.interfaces.ssl.server_ip
#
#         # Open SSL client socket in the DUT
#         sock = wifi_dut.interfaces.wifi.async_sdk_socket(domain="AF_INET",
#                                                          stream_type="SOCK_STREAM",
#                                                          protocol="IPPROTO_TCP")
#         assert sock == 0, "Socket id received is wrong. expected is 0"
#         logger.info(
#             f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
#         logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
#         # Enable ssl option for socket opened
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
#         time.sleep(2)
#         local_port = randint(5001, 60000)
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
#                                       timeout=15)
#         error_code = None
#         try:
#             wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=5001)
#         except Exception as err:
#             error_match = re.search("status:(.*)", str(err))
#             if error_match:
#                 error_code = error_match.group()
#                 logger.info(f"error_code: {error_code}")
#         assert error_code, "DUT sent error code when trying to connect to ssl socket with open_ssl_v1_0 which is expected"
#         logger.info(f"DUT sent error code when trying to connect to ssl socket with open_ssl_v1_0 which is expected")
#
#         openssl.interfaces.server.stop()
#         wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
#
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger.info("Stop Sniffer finally")
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#         decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#         logger.info(f"DECRYPTION KEY-->{decryption_key}")
#
#         ssl_pkt = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"],
#                                                        capture_filename,
#                                                        ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
#         if len(ssl_pkt['tls']) > 0:
#             for i in ssl_pkt['tls']:
#                 if re.search(".*Client Hello", i):
#                     version = re.search("Version:.*", i).group(0)
#                     logger.info(f"TLS VERSION USED BY CLIENT is--->{version}")
#                     assert "TLS 1.0" in version, "TLS version mismatch, expected TLS VERSION 1.2 to be sent by DUT"
#                     assert "Client Hello" in i, "Client Hello packet missed"
#         else:
#             logger.info(f"SSL packets are not found")
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.SSL
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C19113')
def test_wifi_sdk_ssl_server_1_0version_client_1_0_testcase_c19113(
        wifi_sniffer, wifi_dut, wifi_access_point, openssl, logger, sl_collections,
        ssl_server, wifi_client, request
):
    """
        Open ssl server socket in DUT with TLS version 1.0 and connect SSL client to the DUT
        PASS if client connection to DUT status is success else FAIL
    """
    try:
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0],
                                                                 associated=False, power_save=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        logger.info(f"Applying performance profile mode")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        port1 = ssl_server.interfaces.ssl.config['device_port1']

        # Open ssl server socket in remote device-Port1
        ssl_server.interfaces.ssl.start_server(
            port=port1, version='ssl_1'
        )
        server_ip = ssl_server.interfaces.ssl.server_ip

        # Open SSL client socket in the DUT
        sock = wifi_dut.interfaces.wifi.async_sdk_socket(domain="AF_INET",
                                                         stream_type="SOCK_STREAM",
                                                         protocol="IPPROTO_TCP")
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(
            f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_0")
        time.sleep(2)
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                      timeout=15)
        time.sleep(2)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1,
                                                  timeout=15)
        buffer_length = 1370
        # RX throughput test: server sends, DUT receives
        socket_no = 1
        pkt_count = 10000
        duration = 60
        ssl_server.interfaces.ssl.send_data(socket_no, pkt_count, msg_length=buffer_length,
                                            duration=duration)
        time.sleep(80)
        bytes_sent = ssl_server.interfaces.ssl.data_send_stats(socket_no)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock, no_of_pkts="pkt_count", ttl=30)
        logger.info(f"*** result of rx_stats in wifi dut {result}")
        bytes_received = int(result)
        logger.info(f"bytes sent by remote peer -> {bytes_sent}")
        logger.info(f"bytes received on socket {sock} -> {bytes_received}")
        time.sleep(2)
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger.info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        time.sleep(5)
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

#
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
#         "features": Si91xFeatureBitMap.Default,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
#         | Si91xTCPIPFeatureBitMap.SSL
#         | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
#         | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
#         "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
#         | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
#         ],
#     },
# )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
# def test_wifi_sdk_tcp_retransmission_functionality_over_ssl_server_after_remote_terminate_event_C19126(wifi_dut,
#                                                                                                   wifi_access_point,
#                                                                                                   wifi_sniffer, openssl,sl_collections,
#                                                                                                   logger):
#     """
#         TCP retransmission functionality over ssl server socket
#         PASS if remote terminate event is received after closing the client socket else fail.
#     """
#     try:
#         capture_filename = "test_sdk_tcp_retransmission_functionality_over_ssl_server_after_remote_terminate_event_C19126"
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         # configure interface for the channel of the access point
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel
#         )
#
#         dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
#         logger.info(f"DUT MAC_Address: {dut_mac_address}")
#
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         #bt power save to be included
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_parms=[0, 4, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SO_SSL_V_1_2_ENABLE)
#         assert sock == 0, "Socket id received is wrong. expected is 0"
#         logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
#         logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
#         TCP_MAX_RETRY = 10
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
#                                                  TCP_MAX_RETRY)
#
#         # Enable ssl option for socket opened
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
#                                                  SocketOptions.SSL_ENABLE)
#         logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_2_ENABLE} for the socket-id->{sock} using "
#                     f"rsi_setsockopt API")
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_2_ENABLE,
#                                                  SocketOptions.SSL_ENABLE)
#
#         logger.info(f"TLS VERSION USED BY DUT SERVER--->{SocketOptions.SO_SSL_V_1_2_ENABLE}")
#
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
#                                       timeout=15)
#         wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1)
#
#         th_start = Thread(target=dut_server_accept, args=(wifi_dut, sock, logger))
#         th_start.start()
#
#         logger.info(f"Stating the open ssl client with tls version 1")
#         openssl.interfaces.client.start(host=device_ip, port=5001)
#         th_start.join(timeout=10)
#         time.sleep(5)
#
#         wifi_dut.interfaces.wifi.wlan_get_status()
#
#         buffer_length = 200
#
#         data = "".join(
#             random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
#         )
#         buff_len = len(data)
#         logger.info(f"DATA sent from remote PC to dut {data}")
#         openssl.interfaces.client.send_message(data)
#         time.sleep(5)
#         buffer_length, buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=1)
#         logger.info(f"Data received on dut {buffer}")
#         assert data == buffer.decode(), "Date received on dut does not match the data sent from host"
#         openssl.interfaces.client.stop()
#         time.sleep(10)
#         buffer_length, buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=1)
#
#         since_time = 0
#         events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
#         for event in events:
#             if event.event_type == RS9116AsyncEventType.TCP_REMOTE_TERMINATE:
#                 logger.info("Received TCP_REMOTE_TERMINATE event")
#                 logger.info(f"Received the Event Type {event.event_type}, Event data {event.event_data}")
#                 remote_terminate = event.event_data
#                 assert remote_terminate, f"unable to find remote terminate event"
#
#         wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
#         wifi_dut.interfaces.wifi.leave()
#         validation = True
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#
#         packet_filter1 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0))'
#         packet_filter2 = f'((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1))'
#
#         logger.info("association request packet")
#         assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
#             'packet_count'], 'Unable to find association request and association response packets'
#         logger.info("association response packet")
#         assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
#             'packet_count'], 'Unable to find association request and association response packets'
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)