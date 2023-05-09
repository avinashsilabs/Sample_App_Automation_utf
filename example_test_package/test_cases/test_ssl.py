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


@pytest.mark.config("wifi_dut",
                    wifi={"tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.DHCPv6Client})
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
            ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60, version=6)
            ip_fail = 0
            break
        except:
            logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    if ip_fail:
        logger.info(f"DUT unable to get IP address")
        assert ip_fail == 0, "ip setting in DUT has failed"
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    # device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_address, version=6)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)
    return mac_address, device_ip


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


def logger():
    return get_logger(__name__)


@pytest.mark.config("wifi_dut",
                    wifi={"tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.DHCPv6Client})
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


@pytest.mark.config("wifi_dut",
                    wifi={"tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.DHCPv6Client})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_server_testcase_ipv6_TC19110(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_client, logger
):
    try:
        capture_filename = "test_ssl_server_testcase_TC19110"
        pkt_count = 5000
        buffer_length = 1300
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        dut_mac_address, device_ip = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
        # The below api parses DUTs IP address
        # device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp  socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001, version=6)
        wifi_dut.interfaces.wifi.listen(sock, backlog=1)
        # Connect from third party device to the socket opened in the DUT
        ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001, ip_version=6)
        # DUT
        socket_id = wifi_dut.interfaces.wifi.accept(sock, version=6)
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

        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"], capture_filename,
                               mode=0)
    except Exception as error:
        raise error
    finally:
        dut_clean_up(wifi_dut)
