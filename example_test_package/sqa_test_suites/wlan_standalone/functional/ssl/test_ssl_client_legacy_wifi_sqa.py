# Test author: Vinod.G
# Test suite: SSL_CLIENT
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


def dut_recovery(wifi_dut, error):
    recovery_error_codes = ['0xffffffe2', '0xffffffd5']
    for error_code in recovery_error_codes:
        if error_code in str(error):
            logger().info('******* Initiating DUT Recovery using Reset **********')
            wifi_dut.interfaces.wifi.reset()


def dut_clean_up(wifi_dut):
    try:
        logger().info("Closing all opened sockets")
        wifi_dut.interfaces.wifi.close_sockets()
        logger().info("Disconnect from AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        # wifi_dut.interfaces.wifi.inited = False
        time.sleep(3)
    except:
        logger().info("******* Recovering the DUT using reset **********")
        wifi_dut.interfaces.wifi.reset()
        time.sleep(20)


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
            ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=120)
            ip_fail = 0
            break
        except:
            logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(15)
    if ip_fail:
        logger.info(f"DUT unable to get IP address")
        assert ip_fail == 0, "ip setting in DUT has failed"
    # The below two apis put DUT to power save. Both Wi-Fi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)
    return mac_address


def packet_check(wifi_sniffer, logger, decryption_key: str, dut_mac_address, ap_bssid, print_layers: list,
                 capture_filename,
                 mode=0) -> Dict[str, int]:
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    logger.info(f"FILE NAME {file_name}")
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
    true_value = False
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
            if layer_name == "tls":
                tls_layer = str(layer)
                if not ((re.search(".*Application Data Protocol:", tls_layer)) or (
                        re.search(".*Ignored Unknown Record", tls_layer))):
                    if (re.search(".*Receiver address:", mac_layer) and re.search(".*Transmitter address:", mac_layer)):
                        Received = re.compile(r'Receiver address: (([0-9a-fA-F]:?){12})')
                        receiver_address = re.search(Received, mac_layer).group()
                        Transmit = re.compile(r'Transmitter address: (([0-9a-fA-F]:?){12})')
                        Transmitter_address = re.search(Transmit, mac_layer).group()
                        logger.info(f">>>>>>{receiver_address}>>>>>>{Transmitter_address}")
                    result.append(tls_layer)
                    logger.info(f"******************{tls_layer}")
                else:
                    true_value = True
                    break

        if true_value:
            break

    return result


def pdu_switch(switch, sleep_time, logger):
    logger.info("Turning off the AP")
    switch.interfaces.pdu_switch.turn_off()
    logger.info("Successfully powered off AP")
    time.sleep(sleep_time)
    logger.info("Again turning on the AP")
    switch.interfaces.pdu_switch.turn_on()


def join_get_ip_ssl(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger, cert1=None, cert2=None,
                    cert3=None, listen_interval_feature=False, listen_interval=1600, rejoin_params=None):
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")

    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

    if not rejoin_params:
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=20,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
    else:
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_params[0],
                                        scan_interval=rejoin_params[1],
                                        beacon_missedcount=rejoin_params[2],
                                        first_time_retry=rejoin_params[3])
    if listen_interval_feature:
        # DUT connects to AP after join_ap API is executed
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromPowerSave,
                                         )
    else:
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    if cert1:
        # The below API loads ca-cert into DUT at cert index 0
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                     cert_index=0,
                                                     )
    if cert2:
        # The below API loads ca-cert into DUT at cert index 1
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                     cert_index=1,
                                                     )
    if cert3:
        # The below API loads ca-cert into DUT at cert index 2
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                     cert_index=2,
                                                     )

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    if listen_interval_feature:
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                            RS9116PowerSaveProcedureTypes.FastPowerSave,
                                                            listen_interval=listen_interval)

    else:
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, 10)
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
            "ca_cert": "ca-chain.cert.pem",
            "set_send_feature_frame": True,
        }
    )
]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_client_testcase_TC19109(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger
):
    try:
        capture_filename = "test_ssl_client_testcase_TC19109"
        pkt_count = 20000
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        bytes_sent = (pkt_count * buffer_length)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server()
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
        assert_packet_check = (0.95 * float(bytes_sent))
        logger.info(f"Number of bytes sent by dut {assert_packet_check}")
        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
        assert bytes_received >= int(
            assert_packet_check), f"Number of bytes sent by DUT and received on the remote peer are" \
                                  f"not matched on socket {server_socket_no} "
        logger.info(
            f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
        # Close socket 1
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger.info("Successfully closed opened socket in the DUT")
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

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename,
                               mode=0)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.parametrize("repeat", [100])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_client_connect_close_sequence_testcase_C19130(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, repeat
):
    try:
        capture_filename = "test_ssl_client_connect_close_sequence_testcase_C19130"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        fail_count = 0
        for iteration in range(0, repeat):
            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server()
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, f"iteration no->{iteration}:Socket id received is wrong. expected is 0"
            logger.info(
                f"iteration no->{iteration}: Successfully opened tcp client socket and socket id received is {sock} which "
                f"is expected")

            logger.info(
                f"iteration no->{iteration}: Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)

            local_port = randint(5001, 60000)
            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            try:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
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
            wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
            server_socket_no = 1
            # SSL server receives the data over ssl socket
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
            logger.info(f"iteration no->{iteration}: Data received on remote socket opened is {data_receive}")
            assert data_sent == data_receive.decode(), f"iteration no->{iteration}:Data sent by DUT and received on " \
                                                       f"server is matching "
            logger.info(f"iteration no->{iteration}: Data sent by DUT and received on server is matching")
            # Close socket 1
            result = wifi_dut.interfaces.wifi.close_socket(sock)
            assert b"success" in result, f"iteration no->{iteration}:unable to close opened ssl socket in the dut"
            logger.info(f"iteration no->{iteration}: Successfully closed opened socket in the DUT")

            if fail_count:
                logger.info(f"{fail_count} times failed to connect to the server out of {repeat} iterations")
            assert fail_count == 0, f"{fail_count} times failed to connect to the server out of {repeat} iterations"
            time.sleep(1)
            ssl_server.interfaces.ssl.stop_server()

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

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename,
                               mode=0)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_client_tx_rx_bidirectional_testcase_TC19129(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger
):
    try:
        capture_filename = "test_ssl_client_tx_rx_bidirectional_testcase_TC19129"
        pkt_count = 10000
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        bytes_sent = (pkt_count * buffer_length)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server()
        ssl_server.interfaces.ssl.start_server(port=port2)
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE,
                                                               socket_flag=SocketType.ASYNCHRONOUS)

        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        logger.info(f"Setting TCP-RETRY limit to {SocketOptions.TCP_MAX_RETRY} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        local_port = randint(5001, 20000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

        sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock1 == 1, "Socket id received is wrong. expected is 1"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock1} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock1} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        local_port = randint(20001, 40000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock1, device_ip, local_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)
        # pkt_count = 1000
        ssl_server.interfaces.ssl.send_data(1, pkt_count, msg_length=buffer_length, duration=300)
        ssl_server.interfaces.ssl.data_receive(2, pkt_count, buffer_length)
        logger.info("Start tx on the DUT on socket_id1")
        result = wifi_dut.interfaces.wifi.send_data_pkts(sock1, buffer_length, pkt_count)
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
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
        bytes_received = int(result.split(b":")[1])
        logger.info(f"bytes received on socket {sock} -> {bytes_received}")
        logger.info(f"Bytes sent by remote peer {bytes_sent} on socket {1}")
        assert_packet_check = (0.95 * float(bytes_sent))
        # assert bytes_received == bytes_sent, "Packet loss observed while receive test"
        assert bytes_received >= assert_packet_check, "Packet loss observed while receive test"
        logger.info(
            f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
        result = wifi_dut.interfaces.wifi.close_socket(sock1)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger.info(f"Successfully closed opened socket {sock1} in the DUT")
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

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename,
                               mode=0)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut)


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
def test_ssl_client_cipher_list_testcase_TC19132(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger,
                                                 cipher_list):
    try:
        capture_filename = "test_ssl_client_cipher_list_testcase_TC19132"
        pkt_count = 20000
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        bytes_sent = (pkt_count * buffer_length)
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
            logger.info(f"Running SSL test when cipher suite selected is {cipher_str}")
            wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)
            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server()
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, f"Socket id received is wrong. expected is 0 when cipher suite selected is {cipher_str}"
            logger.info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected when "
                f"cipher suite selected is {cipher_str}")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API when cipher suite "
                        f"selected is {cipher_str}")
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
            logger.info(f"Sending data {data_sent} over socket_no->{sock} when cipher suite selected is {cipher_str}")
            # DUT sends 100 bytes of data over ssl socket
            wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
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
            result = wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
            logger.info(f"Number of bytes sent by dut {result}")
            bytes_sent = result
            assert_packet_check = (0.95 * float(bytes_sent))
            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
            assert bytes_received >= assert_packet_check, f"Number of bytes sent by DUT and received on the remote peer are" \
                                                          f"not matched on socket {server_socket_no} when cipher suite selected is {cipher_str}"
            logger.info(
                f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received} when cipher suite selected is {cipher_str}")
            # Close socket 1
            result = wifi_dut.interfaces.wifi.close_socket(sock)
            assert b"success" in result, "unable to close opened ssl socket in the dut when cipher suite selected is {" \
                                         "cipher_str} "
            logger.info("Successfully closed opened socket in the DUT when cipher suite selected is {cipher_str}")

            ssl_server.interfaces.ssl.stop_server()

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

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename,
                               mode=0)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
def test_ssl_client_cipher_suite_mismatch_testcase_TC19133(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server,
                                                           logger):
    try:
        capture_filename = "test_ssl_client_cipher_suite_mismatch_testcase_TC19133"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        logger.info(
            f"Opening SSL server socket remotely with cipher suite->{Cipher.BIT_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA}")
        wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=Cipher.BIT_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)
        logger.info(f"Cipher suite selected in DUT is ECDHE-RSA-AES256-SHA384")
        ssl_server.interfaces.ssl.start_server(cipher_list="ECDHE-RSA-AES256-SHA384")
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
        with pytest.raises(WlanError) as exc_info:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
        assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"
        logger.info(f"DUT returned {exc_info.value.error_code} when cipher suite is mismatched")
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
        packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                     capture_filename, mode=0)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        wifi_dut.interfaces.wifi.inited = False
        dut_clean_up(wifi_dut)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_socket_limit_testcase_TC19121(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger):
    try:
        capture_filename = "test_ssl_socket_limit_testcase_TC19121"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server()
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=5002)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=5003)

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        local_port = randint(5001, 20000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5001)

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
        assert sock == 1, "Socket id received is wrong. expected is 1"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        local_port = randint(20001, 40000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5002)

        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
        assert sock == 2, "Socket id received is wrong. expected is 2"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        local_port = randint(40001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)

        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5003)
        assert exc_info.value.error_code == 0xD3, "Observed wrong error code, expected is 0xD3"
        logger.info(f"DUT sent error code->{exc_info.value.error_code} when trying to open third ssl socket which is "
                    f"expected")
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
        packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                     capture_filename, mode=0)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        wifi_dut.interfaces.wifi.inited = False
        dut_clean_up(wifi_dut)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_client_version_1_2_testcase_TC19119(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger):
    try:
        capture_filename = "test_ssl_client_version_1_2_testcase_TC19119"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port1, version="ssl_1.2")
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_0_ENABLE} for the socket-id->{sock} using "
                    f"rsi_set_sockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_0_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        time.sleep(3)
        with pytest.raises(WlanError) as exc_info:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
        assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"
        logger.info(f"DUT returned {exc_info.value.error_code} error when trying to connect to SSL server operating at "
                    f"version 1.2 and version selected in DUT is 1.0")
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
        packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                     capture_filename, mode=0)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        wifi_dut.interfaces.wifi.inited = False
        dut_clean_up(wifi_dut)


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
def test_ssl_max_sockets_testcaseTC19128(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2):
    try:
        capture_filename = "test_ssl_max_sockets_testcaseTC19128"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)

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
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            if sock_count == 0:
                assert sock == 0, f"socket id received is wrong, expected is 0"
            else:
                assert sock == 1, f"socket id received is wrong, expected is 1"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            logger.info(
                f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
            if sock_count == 0:
                cert_index = SocketOptions.CERT_INDEX0
            elif sock_count == 1:
                cert_index = SocketOptions.CERT_INDEX1

            logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       cert_index)
            if sock_count == 0:
                socket_port = port1
            elif sock_count == 1:
                socket_port = port2

            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

        socket_no = [1, 2]

        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length, pkt_rcv_timeout=10)

        result = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=3, data_len=buffer_length,
                                                                     time_interval=600,
                                                                     number_of_pkts=pkt_count, timeout=620)

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
            result = wifi_dut.interfaces.wifi.close_socket(sock_count)
            assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
            logger.info(f"Successfully closed socket_id->{sock_count}")
        wifi_dut.interfaces.wifi.leave()
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
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut)


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
def test_ssl_client_tx_rejoin_length_1460_20_C19134(
        wifi_dut, wifi_access_point, wifi_sniffer, ssl_server, switch, cert1, logger):
    try:
        capture_filename = "test_ssl_client_tx_rejoin_length_1460_C19134"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length0 = ssl_server.interfaces.ssl.config['buffer_length']
        buffer_length1 = 20
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        pkt_count = 5000

        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        # DUT connects to AP after join_ap API is executed
        rejoin_params = [40, 6, 40, 0]
        dut_mac_address = join_get_ip_ssl(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                          rejoin_params=rejoin_params)

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        logger.info(f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX0)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

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
            thread = Thread(target=pdu_switch, args=(switch, sleep_time, logger), )

            thread.start()
            result = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=1, data_len=buffer_length,
                                                                         time_interval=550,
                                                                         number_of_pkts=pkt_count, timeout=700)
            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(1)
            assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                 f"not matched on socket {1} "

        wifi_dut.interfaces.wifi.close_socket(sock)
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut)


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
def test_ssl_client_rx_while_rejoining_C19135(switch, wifi_dut, wifi_access_point, wifi_sniffer, ssl_server, cert1,
                                              logger):
    try:
        capture_filename = "test_ssl_client_rx_while_rejoining_C19135"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length0 = ssl_server.interfaces.ssl.config['buffer_length']
        buffer_length1 = 20
        port1 = ssl_server.interfaces.ssl.config['device_port1']

        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        # DUT connects to AP after join_ap API is executed
        rejoin_params = [20, 6, 40, 0]
        # rejoin_params = [40, 6, 40, 0]
        dut_mac_address = join_get_ip_ssl(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                          rejoin_params=rejoin_params)

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        logger.info(f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX0)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

        for i in range(2):
            buffer_length = eval("buffer_length" + str(i))
            logger.info(f"************************buffer_length{buffer_length}")
            bytes_sent = (pkt_count * buffer_length)
            socket_no = [1]
            for socket in socket_no:
                ssl_server.interfaces.ssl.send_data(1, pkt_count, msg_length=buffer_length)
            sleep_time = 0
            thread = Thread(target=pdu_switch, args=(switch, sleep_time, logger), )
            thread.start()
            buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock, data_len=buffer_length,
                                                                                timeout=20)
            logger.info(f"bytes received on socket {sock} -> {buffer_length_rx}")
            assert buffer_length == buffer_length_rx, "Packet loss observed while receive test"

        wifi_dut.interfaces.wifi.close_socket(sock)
        wifi_dut.interfaces.wifi.leave()

        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
    except Exception as error:
        dut_recovery(wifi_dut, error)
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
def test_ssl_client_1_2version_server_1_0_testcase_TC19120(wifi_sniffer, wifi_dut, wifi_access_point, openssl,
                                                           wifi_client, logger):
    try:
        capture_filename = "test_ssl_server_1_0version_client_1_2_testcase_TC19120"
        port_connect = randint(5001, 5010)
        result = wifi_dut.interfaces.wifi.version()
        logger.info(f"DUT firmware version: {result}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        # configure interface for the channel of the access point
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
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
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
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
        openssl.interfaces.server.start(port=port_connect, tls_version="-tls1")
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_2_ENABLE} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_2_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        time.sleep(3)
        host_ip = wifi_client.interfaces.wifi.get_ip_address()

        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.connect_to_server(sock, host_ip, server_port=port_connect)
        assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"

        openssl.interfaces.server.stop()
        wifi_dut.interfaces.wifi.close_socket(sock)
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

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename, mode=0)
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
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        wifi_dut.interfaces.wifi.inited = False
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
def test_ssl_client_1_0version_server_1_0_testcase_TC19117(
        wifi_sniffer, wifi_dut, wifi_access_point, openssl, wifi_client, logger):
    try:
        capture_filename = "test_ssl_server_1_0version_client_1_0_testcase_TC19117"
        ping_count = 10
        port_connect = 5001
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

        openssl.interfaces.server.start(port=5001, tls_version="-tls1")

        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_0_ENABLE} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_0_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)

        host_ip = wifi_client.interfaces.wifi.get_ip_address()

        wifi_dut.interfaces.wifi.connect_to_server(sock, host_ip, server_port=port_connect)

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
            wifi_dut.interfaces.wifi.send_data(sock, buffer_length, data)

        out = openssl.interfaces.server.get_messages(timeout=100)
        result = out[-1]
        logger.info(f"Total data sent from DUT {data_final}")
        logger.info(f"*************data received*************** {result}")

        assert data_final == result, "Data received doesn't match"

        openssl.interfaces.server.stop()
        wifi_dut.interfaces.wifi.close_socket(sock)
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
        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"],
                               capture_filename,
                               mode=0)
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
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut)
