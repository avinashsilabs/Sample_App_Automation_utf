from typing import Dict
import time
import pytest
import re
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf import UtfDatabaseProperties
from utf.utils.stopwatch import Stopwatch
import string
import random
from utf.utils.iperf.iperf_utils import ping
from random import randint
from datetime import datetime
import uuid
from test_ssl_advertize_ciphers_rsa import get_cipher_list, select_cipher_list, dut_clean_up
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
    Cipher_Extended_917,
    DeviceConstants,
    Cipher_Extended_BIT_917,
    )

"""The testcases added in this file run below test steps for DUT-RS9117
        1. Configuration of DUT in 2G
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
        1. Expansion_board(RS9117)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC Wifi Sniffer
"""

"""Author : Harshitha"""


def logger():
    return get_logger(__name__)

def select_extended_cipher_list(cipher_list):
    cipher = 0
    for count in cipher_list:
        for cipher_mem in Cipher_Extended_BIT_917:
            if count in str(cipher_mem):
                cipher = cipher | cipher_mem.value
    return cipher

def join_ap(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, capture_filename, utf_constants, logger):

    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    dut_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=True)
    logger.info(f"device_ip, device_mac : {dut_ip}, {dut_mac_address}")



class Extended:
    def extended_cipher_list(self, wifi_dut, cipher_list, extended_cipher_list):
        if len(cipher_list):
            select_cipher_list(cipher_list)
            wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=0)
            cipher_extended = select_extended_cipher_list(extended_cipher_list)
            wifi_dut.interfaces.wifi.select_extended_ssl_cipher(cipher_list=cipher_extended)

class Ssl_connection:

    def single_socket(self, wifi_dut, ssl_server, logger):
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        time.sleep(3)
        ssl_server.interfaces.ssl.start_server()
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        logger.info(f"Enable ssl option for socket opened")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_3_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        local_port = randint(5001, 60000)
        logger.info(f"*******Socket binds at device_ip with port 5001 in DUT*****")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        logger.info(f"****ssl socket opened in DUT connects to the server****")
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
        logger.info(f"****API returns 100 bytes of random data*****")
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        logger.info(f"Sending data {data_sent} over socket_no->{sock}")
        logger.info(f" ******DUT sends 100 bytes of data over ssl socket*********")
        wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
        server_socket_no = 1
        logger.info(f"***SSL server receives the data over ssl socket****")
        data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
        logger.info(f"Data received on remote socket opened is {data_receive}")
        assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
        logger.info("Data sent by DUT and received on server is matching")
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger.info("Successfully closed opened socket in the DUT")
        wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
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
            "band": 0,
            "ca_cert": "ca-chain.cert.pem",
            "set_send_feature_frame": True,
        }
    )

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [["TLS_CHACHA20_POLY1305_SHA256"]])
def test_ssl_connection_powersave_chacha20poly1305_C37609(wifi_dut,wifi_sniffer, wifi_access_point, rs_helper,utf_constants,
                                                         cipher_list, ssl_server, logger):
    try:

        capture_filename = "test_ssl_connection_powersave_chacha20poly1305_C37609"
        logger.info(f"Test Case Name : {capture_filename}")
        extended_cipher_list = cipher_list
        expected_cipher = extended_cipher_list
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {dut_mac_address}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f"AP bssid {ap_bssid}")
        join_ap(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, capture_filename, utf_constants, logger)
        list = Extended()
        list.extended_cipher_list(wifi_dut, cipher_list, extended_cipher_list)
        ssl = Ssl_connection()
        ssl.single_socket(wifi_dut, ssl_server, logger)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")

        validation = True
        packet_filter1 = f"(wlan.fc.type_subtype == 0x0008) and (wlan.sa == {ap_bssid})"

        packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")

        packet_filter3 = f" (wlan.addr == {dut_mac_address}) && (wlan.addr == {ap_bssid})"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)

        logger.info(f"Validating beacons")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find beacons in sniffer'
        logger.info("Successfully validated sniffer packets")

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        cipher_suite = get_cipher_list(wifi_sniffer, logger, decryption_key, dut_mac_address, ["tls"], capture_filename, mode=0)
        if not (len(cipher_suite) > 0):
            logger.info(f"tls client hello packet is not captured or one of the wifi 4-way handshake pkt "
                           "is "
                           "not captured")
        assert (len(cipher_suite) > 0), f"tls client hello packet is not captured or one of the wifi 4-way handshake " \
                                        f"pkt is not captured "
        cipher_suite = cipher_suite[0][1]
        logger.info(
            f"******As per sniffer capture, cipher suite advertised by DUT {dut_mac_address}-> {cipher_suite}*******")

        if not (cipher_suite == expected_cipher):
            logger.info(f"******cipher suite mismatched ******\nexpected "
                        f"is {expected_cipher}\n But"
                        f"observed {cipher_suite}")
    except Exception as e:
        logger.info(f"\n******Testcase failed with : {e}******")
        raise e
    finally:
        dut_clean_up(wifi_dut)

