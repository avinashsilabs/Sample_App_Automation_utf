# Test author: Vinod.G
# Test suite: SSL_SERVER
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
    RS9116AsyncEventType,
    SocketOptions,
    SocketType,
    Cipher,
    RS9116PowerSaveProcedureTypes,
    DeviceConstants,
)
from utf.interfaces.wifi import WlanError
import string
import random
from utf.utils.iperf.iperf_utils import ping
import time
import re
import uuid
from datetime import datetime
from typing import Dict
from threading import Thread
from utf.utils.logger import get_logger

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Load ssl certificates in the DUT
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Create a new TCP/IP server socket over ssl 
        6. Bind the socket with DUT ip address
        7. Connect the server socket with third party client socket 
        8. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""


def logger():
    return get_logger(__name__)

def dut_clean_up(wifi_dut):
    try:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        time.sleep(3)
    except:
        logger().info("******* Recovering the DUT using reset **********")
        wifi_dut.interfaces.wifi.reset()
        time.sleep(20)
def dut_server_accept(wifi_dut, sock, logger):
    wifi_dut.interfaces.wifi.accept(socket_id=sock)


def packet_check(wifi_sniffer, logger, decryption_key: str, dut_mac_address, ap_bssid, print_layers: list,
                 capture_filename,
                 mode=0) -> Dict[str, int]:
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    result = []
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {ap_bssid})'
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
            if layer_name == "tls":
                tls_layer = str(layer)
                filtered_packet = str(packet)
                filtered_packet = filtered_packet.split("Layer ")
                tls_layer_pkt = ""
                ra_address = ""
                ta_address = ""
                logger.info(f"DUT_MAC_ADDRESS: {dut_mac_address},AP_BSSID: {ap_bssid}")
                for layerp in filtered_packet:
                    if ((
                    (re.search(".*Receiver address:", layerp) and re.search(".*Transmitter address:", layerp))) or (
                    re.search(".*TLS:", layerp))):
                        if (re.search(".*TLS:", layerp)):
                            tls_layer_pkt = layerp
                        if (re.search(".*Receiver address:", layerp) and re.search(".*Transmitter address:", layerp)):
                            Received = re.compile(r'Receiver address: (([0-9a-fA-F]:?){12})')
                            receiver_address = re.search(Received, layerp).group()
                            ra_address = (re.search(Received, layerp).group(1)).lower()
                            Transmit = re.compile(r'Transmitter address: (([0-9a-fA-F]:?){12})')
                            Transmitter_address = re.search(Transmit, layerp).group()
                            ta_address = (re.search(Transmit, layerp).group(1)).lower()
                            dut_mac_address_mod = dut_mac_address.lower()
                            ap_bssid_mod = ap_bssid.lower()

                        if ((ra_address == dut_mac_address_mod or ra_address == ap_bssid_mod) and (
                                ta_address == dut_mac_address_mod or ta_address == ap_bssid_mod)) and tls_layer_pkt:
                            logger.info(f">>>>>>{receiver_address}>>>>>>{Transmitter_address}")
                            logger.info(f"TLS HANDSHAKE PACKET{tls_layer_pkt}")
                            result.append(tls_layer_pkt)

    return result

def connect_to_server(client_socket, device_ip, logger, server_port=5001):
    time.sleep(5)
    logger.info(f"Connecting from remote device to DUT socket {(device_ip, server_port)}")
    client_socket.connect_client_tcp(device_ip, server_port)


def send_data_from_client(ssl_client, pkt_count, buffer_length, logger):
    logger.info(f"Sending {pkt_count} number of pkts each with buffer length {buffer_length} from client")
    for count in range(0, pkt_count):
        ssl_client.interfaces.ssl.send_data(buffer_length)


def join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger):
    ping_count = 10
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
            wifi_dut.interfaces.wifi.start_ip(timeout=120, retries=6)
            ip_fail = 0
            break
        except:
            logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(15)
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
    return mac_address


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
            "server_cert": "mosquitto-utf.silabs.com.cert.pem",
            "server_key": "mosquitto-utf.silabs.com.key.pem",
            "set_send_feature_frame": True,
        }
    )
]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_server_testcase_TC19110(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_client, logger
):
    try:
        capture_filename = "test_ssl_server_testcase_TC19110"
        pkt_count = 5000
        buffer_length = 1300
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
        wifi_dut.interfaces.wifi.listen(sock, backlog=1)
        # Connect from third party device to the socket opened in the DUT
        ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001)
        # DUT
        socket_id = wifi_dut.interfaces.wifi.accept(sock)
        # The api returns 100 bytes of random data
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        # DUT sends 100 bytes of data over ssl socket
        wifi_dut.interfaces.wifi.send_data(socket_id, data_length, data_sent)
        # SSL client socket opened in third-party device receives the data
        data_receive = ssl_client.interfaces.ssl.data_recv(data_length)

        if data_sent == data_receive.decode():
            logger.info("Data sent and received is matching")
        # thread = Thread(target=send_data_from_client, args=(ssl_client, pkt_count, buffer_length, logger), )
        # thread.start()
        # logger.info("wait for 300 seconds to receive the data on the socket")
        # time.sleep(300)
        # result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)
        # bytes_received = int(result.split(b":")[1])
        # logger.info(f"bytes received on socket {sock} -> {bytes_received}")
        # assert bytes_received == (pkt_count * buffer_length), "Packet loss observed while receive test"

        result = wifi_dut.interfaces.wifi.close_socket(socket_id)
        assert b"success" in result, "unable to close opened tcp socket"
        logger.info(f"Successfully closed socket_id:{socket_id}  in the DUT")
        # DUT closes the tcp socket
        result = wifi_dut.interfaces.wifi.close_socket(sock)
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

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename,
                               mode=0)
    except Exception as error:
        raise error
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.parametrize("cipher_list", [
    [Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA256, Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA256,
     Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA, Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA]])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_SSLserver_functionality_by_configuring_cipher_suite_in_combination_C113934(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_client, logger, cipher_list
):
    try:
        capture_filename = "test_SSLserver_functionality_by_configuring_cipher_suite_in_combination_C113934"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
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
            wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)
            # The below api opens ssl server socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
            assert sock == 0, "Socket id received is wrong. expected is 0"
            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
            wifi_dut.interfaces.wifi.listen(sock, backlog=1)
            # Connect from third party device to the socket opened in the DUT
            ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001)
            # DUT
            socket_id = wifi_dut.interfaces.wifi.accept(sock)
            # The api returns 100 bytes of random data
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            data_length = len(data_sent)
            # DUT sends 100 bytes of data over ssl socket
            wifi_dut.interfaces.wifi.send_data(socket_id, data_length, data_sent)
            # SSL client socket opened in third-party device receives the data
            data_receive = ssl_client.interfaces.ssl.data_recv(data_length)
            # DUT closes the tcp socket
            result = wifi_dut.interfaces.wifi.close_socket(socket_id)
            assert b"success" in result, "unable to close opened tcp socket"
            # DUT closes the tcp socket
            result = wifi_dut.interfaces.wifi.close_socket(sock)
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

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename,
                               mode=0)
    except Exception as error:
        raise error
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_server_1_0version_client_1_2_testcase_TC19115(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_client, logger
):
    try:
        capture_filename = "test_ssl_server_1_0version_client_1_2_testcase_TC19115"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        # The below api opens ssl server socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE_VERSION_1_0)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_0_ENABLE} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")
        # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_0_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
        wifi_dut.interfaces.wifi.listen(sock, backlog=1)
        # Connect from third party device to the socket opened in the DUT
        ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001, version="ssl_1.2")
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.accept(sock)
        assert exc_info.value.error_code == 0xFFFFFFFF, "DUT sent wrong error code, expected is 0xFFFFFFFF"
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.wlan_get_status()
        assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"
        logger.info(
            f"DUT sent error code->{exc_info.value.error_code} when third-party ssl client operating at version "
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

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename,
                               mode=0)
    except Exception as error:
        raise error
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_server_no_server_cert_testcase_TC19111(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_client, logger
):
    try:
        capture_filename = "test_ssl_server_no_server_cert_testcase_TC19111"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)

        wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLServerCertificate,
                                                   cert_index=0
                                                   )
        wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLServerPrivateKey,
                                                   cert_index=0
                                                   )

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        # The below api opens ssl server socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
        wifi_dut.interfaces.wifi.listen(sock, backlog=1)
        # Connect from third party device to the socket opened in the DUT
        ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.accept(sock)
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

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename,
                               mode=0)
    except Exception as error:
        raise error
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_server_connect_non_ssl_client_testcase_TC19112(
        wifi_sniffer, wifi_access_point, wifi_dut, remote_socket_factory, logger
):
    try:
        capture_filename = "test_ssl_server_connect_non_ssl_client_testcase_TC19112"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        # The below api opens ssl server socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
        wifi_dut.interfaces.wifi.listen(sock, backlog=1)
        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        thread = Thread(target=connect_to_server, args=(client_socket, device_ip, logger, 5001), )
        thread.start()
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.accept(sock)
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

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename,
                               mode=0)
    except Exception as error:
        raise error
    finally:
        dut_clean_up(wifi_dut)


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
def test_ssl_server_1_2version_client_1_0_testcase_TC19116(
        wifi_sniffer, wifi_dut, wifi_access_point, openssl, logger):
    try:
        capture_filename = "test_ssl_server_1_2version_client_1_0_testcase_TC19116"
        ping_count = 10
        result = wifi_dut.interfaces.wifi.version()
        logger.info(f"DUT firmware version: {result}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
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

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )

        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=4,
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

        ip = False
        for i in range(3):
            try:
                wifi_dut.interfaces.wifi.start_ip(timeout=60)
                ip = True
                break
            except:
                logger.info(f"Retrying for {i}times")

        assert ip == True, "Fetching IP failed"

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        # openssl.interfaces.client.start(tls_version="-tls1")
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_V_1_2_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_2_ENABLE} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")

        logger.info(f"TLS VERSION USED BY DUT SERVER--->{SocketOptions.SO_SSL_V_1_2_ENABLE}")
        # # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_2_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
        wifi_dut.interfaces.wifi.listen(sock, backlog=1)

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
        wifi_dut.interfaces.wifi.close_socket(sock)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename,
                               mode=0)

        if len(ssl_pkt) > 0:
            for i in ssl_pkt:
                if re.search(".*Client Hello", i):
                    version = re.search("Version:.*", i).group(0)
                    logger.info(f"TLS VERSION USED BY CLIENT is--->{version}")
                    assert "TLS 1.0" in version, "TLS version mismatch, expected TLS VERSION 1.2 to be sent by DUT"
                    assert "Client Hello" in i, "Client Hello packet missed"
        else:
            logger.info(f"SSL packets are not found")
    except Exception as error:
        raise error
    finally:
        dut_clean_up(wifi_dut)

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
def test_ssl_server_1_0version_client_1_0_testcase_TC19113(
        wifi_sniffer, wifi_dut, wifi_access_point, openssl, logger):
    try:
        capture_filename = "test_ssl_server_1_0version_client_1_0_testcase_TC19113"
        ping_count = 10
        result = wifi_dut.interfaces.wifi.version()
        logger.info(f"DUT firmware version: {result}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
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

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )

        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=4,
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

        ip = False
        for i in range(3):
            try:
                wifi_dut.interfaces.wifi.start_ip(timeout=60)
                ip = True
                break
            except:
                logger.info(f"Retrying for {i}times")

        assert ip == True, "Fetching IP failed"

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        # openssl.interfaces.client.start(tls_version="-tls1")
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_V_1_0_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_0_ENABLE} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")
        # # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_0_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        logger.info(f"TLS VERSION USED BY DUT SERVER--->{SocketOptions.SO_SSL_V_1_0_ENABLE}")

        wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
        wifi_dut.interfaces.wifi.listen(sock, backlog=1)

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
        buffer_length, buffer = wifi_dut.interfaces.wifi.receive_from(1, data_len=buff_len)
        logger.info(f"Data received on dut {buffer}")
        assert data == buffer.decode(), "Date received on dut does not match the data sent from host"

        openssl.interfaces.client.stop()
        wifi_dut.interfaces.wifi.close_socket(sock)


        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename,
                               mode=0)

        if len(ssl_pkt) > 0:
            for i in ssl_pkt:
                if re.search(".*Client Hello", i):
                    version = re.search("Version:.*", i).group(0)
                    logger.info(f"TLS VERSION USED BY CLIENT is--->{version}")
                    assert "TLS 1.0" in version, "TLS version mismatch, expected TLS VERSION 1.2 to be sent by DUT"
                    assert "Client Hello" in i, "Client Hello packet missed"
        else:
            logger.info(f"SSL packets are not found")
    except Exception as error:
        raise error
    finally:
        dut_clean_up(wifi_dut)

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
def test_tcp_retransmission_functionality_over_ssl_server_after_remote_terminate_event_C19126(wifi_dut,
                                                                                              wifi_access_point,
                                                                                              wifi_sniffer, openssl,
                                                                                              logger):
    capture_filename = "test_ssl_server_1_0version_client_1_0_testcase_TC19113"
    ping_count = 10
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
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

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {dut_mac_address}")

    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap"
    )

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                    scan_interval=4,
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

    ip = False
    for i in range(3):
        try:
            wifi_dut.interfaces.wifi.start_ip(timeout=60)
            ip = True
            break
        except:
            logger.info(f"Retrying for {i}times")

    assert ip == True, "Fetching IP failed"

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    # openssl.interfaces.client.start(tls_version="-tls1")
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_V_1_2_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    TCP_MAX_RETRY = 10
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               TCP_MAX_RETRY)

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_2_ENABLE} for the socket-id->{sock} using "
                f"rsi_setsockopt API")
    # # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_2_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    logger.info(f"TLS VERSION USED BY DUT SERVER--->{SocketOptions.SO_SSL_V_1_2_ENABLE}")

    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
    wifi_dut.interfaces.wifi.listen(sock, backlog=1)

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
    buffer_length, buffer = wifi_dut.interfaces.wifi.receive_from(1, data_len=buff_len)
    logger.info(f"Data received on dut {buffer}")
    assert data == buffer.decode(), "Date received on dut does not match the data sent from host"
    openssl.interfaces.client.stop()
    time.sleep(10)
    buffer_length, buffer = wifi_dut.interfaces.wifi.receive_from(1, data_len=buff_len)

    since_time = 0
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
    for event in events:
        if event.event_type == RS9116AsyncEventType.TCP_REMOTE_TERMINATE:
            logger.info("Received TCP_REMOTE_TERMINATE event")
            logger.info(f"Received the Event Type {event.event_type}, Event data {event.event_data}")
            remote_terminate = event.event_data
            assert remote_terminate, f"unable to find remote terminate event"
    wifi_dut.interfaces.wifi.close_socket(sock)
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
