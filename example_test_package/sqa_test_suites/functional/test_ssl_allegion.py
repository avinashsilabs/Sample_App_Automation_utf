import time
import pytest
from devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    SocketOptions,
    RS9116AsyncEventType,
    RS9116OperatingMode,
    DeviceConstants,
    )
from interfaces.wifi import WlanError
from utils import get_tls_certificate_dir
from typing import Dict

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


def get_beacon_interval(wifi_sniffer, decryption_key: str, ap_ssid, mode=0) -> Dict[str, int]:
    mgt_flag = 0
    beacon_interval = 0
    dtim_period = 0
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            mgt_layer = str(layer)
            if layer_name == "wlan":
                if "Type/Subtype: Beacon frame (0x0008)" in mgt_layer:
                    mgt_flag = 1
                else:
                    mgt_flag = 0
                    continue

            if layer_name == "wlan.mgt":
                if mgt_flag:
                    beacon_field_list = mgt_layer.split("\n")
                    for beacon_sub_field in beacon_field_list:
                        if "Beacon Interval" in beacon_sub_field:
                            beacon_interval = float(beacon_sub_field.split(":")[1].split("[Seconds]")[0].strip())
                            beacon_interval = int(beacon_interval * 1000)

                        if "DTIM period" in beacon_sub_field:
                            dtim_period = int(beacon_sub_field.split(":")[1].strip())

                        if "Tag: SSID parameter set" in beacon_sub_field:
                            ssid = beacon_sub_field.split(":")[2].strip()
                            if not (ap_ssid == ssid):
                                beacon_interval = 0
                                dtim_period = 0
                                continue
    return beacon_interval, dtim_period


def get_ntp_list(wifi_sniffer, decryption_key: str, print_layers: list, mode=0) -> Dict[str, int]:
    ntp_capture_list = []
    source_ip = ""
    destination_ip = ""
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "ip":
                ip_layer = str(layer)
                layer_ip = ip_layer.split("\n")
                for count in layer_ip:
                    if "Source" in count:
                        source_ip = count.split(":")[1].strip()
                    if "Destination" in count:
                        destination_ip = count.split(":")[1].strip()

            if layer_name in print_layers:
                ntp_layer = str(layer)
                ntp_capture_list.append(tuple([ntp_layer, packet.sniff_timestamp, source_ip, destination_ip]))
    return ntp_capture_list


def ApWirelessOff(wifi_access_point, wait_time, logger):
    time.sleep(wait_time)
    logger.info(f"Disabling Wireless in AP")
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    logger.info(f"Enabling Wireless in AP")
    wifi_access_point.interfaces.wifi.start_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 20,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_three_ssl_socket_connection_after_reconnection_TC19156(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_three_ssl_socket_connection_after_reconnection_TC19156"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)

    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    # The below API loads ca-cert into DUT at cert index 1
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                 cert_index=1,
                                                 )
    # The below API loads ca-cert into DUT at cert index 2
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                 cert_index=2,
                                                 )

    for count in range(0, 2):
        # DUT connects to AP after join_ap API is executed
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX0)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

        # Open ssl client socket in the DUT
        sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock1 == 1, f"socket id received is wrong, expected is 1"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 1 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX1)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock1, device_ip, port2)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

        # Open ssl client socket in the DUT
        sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock2 == 2, f"socket id received is wrong, expected is 2"

        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 1 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX2)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock2, device_ip, port3)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)

        if count == 1:
            socket_no = [1, 2, 3]
            for socket in socket_no:
                ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)

            if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                socket_no = [1, 2, 3]
                for socket in socket_no:
                    if ssl_server.interfaces.ssl.socket_connection_status(socket):
                        wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                        time.sleep(10)
                        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                        assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote " \
                                                             f"peer " \
                                                             f"not matched on socket {socket} "

                    else:
                        assert f"failed to connect on socket no {socket}"

        if count == 0:
            wifi_access_point.interfaces.wifi.stop_ap()
            ssl_server.interfaces.ssl.stop_server()
            time.sleep(130)
            rejoin_error_recv = 0
            events = wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == RS9116AsyncEventType.RejoinError:
                    rejoin_error_recv = 1
            if rejoin_error_recv:
                logger.info(f"DUT received rejoin failure error as configured AP is powered off")
                wifi_dut.interfaces.wifi.associated = False
            else:
                assert f"DUT didn't recieve rejoin failure error within time even after AP is powered off"
            wifi_access_point.interfaces.wifi.start_ap()
            # ssl_server.interfaces.ssl.stop_server()
        if count == 1:
            # Close socket 1
            wifi_dut.interfaces.wifi.close_socket(sock)
            # Close socket 2
            wifi_dut.interfaces.wifi.close_socket(sock1)
            # Close socket 3
            wifi_dut.interfaces.wifi.close_socket(sock2)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_three_sockets_connectivity_check_loading_wrong_certs_TC19165(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_ssl_three_sockets_connectivity_check_loading_wrong_certs_TC19165"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)

    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    # The below API loads ca-cert into DUT at cert index 1
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                 cert_index=1,
                                                 )
    # The below API loads ca-cert into DUT at cert index 2
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                 cert_index=2,
                                                 )
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    with pytest.raises(WlanError) as exc_info:
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
    assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1, f"socket id received is wrong, expected is 0"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX1)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock1, device_ip, port2)
    with pytest.raises(WlanError) as exc_info:
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)
    assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    # Open ssl client socket in the DUT
    sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock2 == 2, f"socket id received is wrong, expected is 0"

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX2)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock2, device_ip, port3)
    with pytest.raises(WlanError) as exc_info:
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
    assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_three_sockets_send_data_testcaseTC3918(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_ssl_three_sockets_send_data_testcaseTC3918"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    # The below API loads ca-cert into DUT at cert index 1
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                 cert_index=1,
                                                 )
    # The below API loads ca-cert into DUT at cert index 2
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                 cert_index=2,
                                                 )

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1, f"socket id received is wrong, expected is 1"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX1)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock1, device_ip, port2)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

    # Open ssl client socket in the DUT
    sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock2 == 2, f"socket id received is wrong, expected is 2"

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX2)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock2, device_ip, port3)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)

    socket_no = [1, 2, 3]
    for socket in socket_no:
        ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
        # ssl_server.interfaces.ssl.data_receive(socket, 10000, buffer_length)
    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1, 2, 3]
        for socket in socket_no:
            if ssl_server.interfaces.ssl.socket_connection_status(socket):
                # ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
                wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                time.sleep(10)
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                     f"not matched on socket {socket} "

            else:
                assert f"failed to connect on socket no {socket}"

    # Close socket 1
    wifi_dut.interfaces.wifi.close_socket(sock)
    # Close socket 2
    wifi_dut.interfaces.wifi.close_socket(sock1)
    # Close socket 3
    wifi_dut.interfaces.wifi.close_socket(sock2)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_three_sockets_load_remove_certs_connection_check_testcaseTC3929(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_ssl_three_sockets_load_remove_certs_connection_check_testcaseTC3929"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)

    for iteration in range(0, 2):
        if iteration == 1:
            wifi_dut.interfaces.wifi.leave()
            wifi_dut.interfaces.wifi.associated = False
            # wifi_dut.interfaces.wifi.initialized = False
            time.sleep(120)
        wifi_dut.interfaces.wifi.scan(ssid=None)
        # DUT connects to AP after join_ap API is executed
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        # The below API loads ca-cert into DUT at cert index 0
        if iteration == 0:
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                         cert_index=0,
                                                         )
            # The below API loads ca-cert into DUT at cert index 1
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                         cert_index=1,
                                                         )
            # The below API loads ca-cert into DUT at cert index 2
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                         cert_index=2,
                                                         )
        else:
            for cert_index in range(0, 3):
                wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                                           cert_index=cert_index)
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX0)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)

        if iteration == 0:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
        else:
            with pytest.raises(WlanError) as exc_info:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
            assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"

        # Open ssl client socket in the DUT
        sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock1 == 1, f"socket id received is wrong, expected is 1"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 1 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX1)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock1, device_ip, port2)

        if iteration == 0:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)
        else:
            with pytest.raises(WlanError) as exc_info:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)
            assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"

        # Open ssl client socket in the DUT
        sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock2 == 2, f"socket id received is wrong, expected is 2"

        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 1 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX2)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock2, device_ip, port3)

        if iteration == 0:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
        else:
            with pytest.raises(WlanError) as exc_info:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
            assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"

        if iteration == 0:
            socket_no = [1, 2, 3]
            for socket in socket_no:
                ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)

            if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                socket_no = [1, 2, 3]
                for socket in socket_no:
                    if ssl_server.interfaces.ssl.socket_connection_status(socket):
                        wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                        time.sleep(10)
                        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                        assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote " \
                                                             f"peer " \
                                                             f"not matched on socket {socket} "

                    else:
                        assert f"failed to connect on socket no {socket}"

            # Close socket 1
            wifi_dut.interfaces.wifi.close_socket(sock)
            # Close socket 2
            wifi_dut.interfaces.wifi.close_socket(sock1)
            # Close socket 3
            wifi_dut.interfaces.wifi.close_socket(sock2)
            ssl_server.interfaces.ssl.stop_server()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_three_sockets_shut_down_testcaseTC3923(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_ssl_three_sockets_shut_down_testcaseTC3923"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    # The below API loads ca-cert into DUT at cert index 1
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                 cert_index=1,
                                                 )
    # The below API loads ca-cert into DUT at cert index 2
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                 cert_index=2,
                                                 )

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1, f"socket id received is wrong, expected is 1"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX1)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock1, device_ip, port2)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

    # Open ssl client socket in the DUT
    sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock2 == 2, f"socket id received is wrong, expected is 2"

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX2)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock2, device_ip, port3)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)

    socket_no = [1, 2, 3]
    for socket in socket_no:
        ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
        # ssl_server.interfaces.ssl.data_receive(socket, 10000, buffer_length)
    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1, 2, 3]
        for socket in socket_no:
            if ssl_server.interfaces.ssl.socket_connection_status(socket):
                # ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
                wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                time.sleep(10)
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                     f"not matched on socket {socket} "

            else:
                assert f"failed to connect on socket no {socket}"

    # Close socket 1
    wifi_dut.interfaces.wifi.close_socket(sock)
    # Close socket 2
    wifi_dut.interfaces.wifi.close_socket(sock1)
    # Close socket 3
    wifi_dut.interfaces.wifi.close_socket(sock2)
    sockets_opened, socket_info = wifi_dut.interfaces.wifi.wlan_get_socket_info()
    assert sockets_opened == 0, f"Number of sockets opened in DUT is 0. But shown {sockets_opened} when query " \
                                f"through get_network_params api"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_clear_cert2_TC3920(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_ssl_clear_cert2_TC3920"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)

    for iteration in range(0, 2):
        if iteration == 1:
            time.sleep(120)
            wifi_dut.interfaces.wifi.reset_soft()
            wifi_dut.interfaces.wifi.wireless_init()
        # DUT connects to AP after join_ap API is executed
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        if iteration == 0:
            # The below API loads ca-cert into DUT at cert index
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                         cert_index=0,
                                                         )
            # The below API loads ca-cert into DUT at cert index 1
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                         cert_index=1,
                                                         )
            # The below API loads ca-cert into DUT at cert index 2
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                         cert_index=2,
                                                         )
        if iteration == 1:
            wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate, cert_index=2)

        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX0)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

        # Open ssl client socket in the DUT
        sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock1 == 1, f"socket id received is wrong, expected is 1"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 1 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX1)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock1, device_ip, port2)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

        # Open ssl client socket in the DUT
        sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock2 == 2, f"socket id received is wrong, expected is 2"

        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 1 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX2)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock2, device_ip, port3)
        if iteration == 0:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
        else:
            with pytest.raises(WlanError) as exc_info:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
            assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"

        if iteration == 0:
            socket_no = [1, 2, 3]
        else:
            socket_no = [1, 2]
        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)

        if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
            if iteration == 0:
                socket_no = [1, 2, 3]
            else:
                socket_no = [1, 2]
            for socket in socket_no:
                if ssl_server.interfaces.ssl.socket_connection_status(socket):
                    # ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
                    wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                    time.sleep(10)
                    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                    assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                         f"not matched on socket {socket} "

                else:
                    assert f"failed to connect on socket no {socket}"

        # Close socket 1
        wifi_dut.interfaces.wifi.close_socket(sock)
        # Close socket 2
        wifi_dut.interfaces.wifi.close_socket(sock1)
        if iteration == 0:
            # Close socket 3
            wifi_dut.interfaces.wifi.close_socket(sock2)
            ssl_server.interfaces.ssl.stop_server()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_socket_check_TC19158(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_socket_check_TC19158"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    # The below API loads ca-cert into DUT at cert index 1
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                 cert_index=1,
                                                 )
    # The below API loads ca-cert into DUT at cert index 2
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                 cert_index=2,
                                                 )

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
    server_ip = ssl_server.interfaces.ssl.hostname_or_ip_address()

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1, f"socket id received is wrong, expected is 1"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX1)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock1, device_ip, port2)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

    # Open ssl client socket in the DUT
    sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock2 == 2, f"socket id received is wrong, expected is 2"

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX2)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock2, device_ip, port3)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
    socket1 = tuple([(sock + 1), 0, port1, port1, server_ip])
    socket2 = tuple([(sock1 + 1), 0, port2, port2, server_ip])
    socket3 = tuple([(sock2 + 1), 0, port3, port3, server_ip])

    sockets_opened, socket_info = wifi_dut.interfaces.wifi.wlan_get_socket_info()
    assert sockets_opened == 3, f"Number of sockets opened in DUT is 3. But shown {sockets_opened} when query " \
                                f"through get_network_params api"
    iter = 0
    if sockets_opened:
        for count in socket_info:
            iter = iter + 1
            if iter == 1:
                assert count[0] == socket1[
                    0], f"socket id received in network query response is wrong for socket {iter} expected is {socket1[0]} "
                assert count[1] == socket1[
                    1], f"socket type received in network query response is wrong for socket {iter} expected is {socket1[1]} "
                assert count[2] == socket1[
                    2], f"source port received in network query response is wrong for socket {iter} expected is {socket1[2]}"
                assert count[3] == socket1[3], f"destination port received in network query response is wrong for " \
                                               f"socket {iter} expected is {socket1[3]} "
                assert count[4] == socket1[
                    4], f"server ip received in network query response is wrong for socket {iter} expected is {socket1[4]}"

            elif iter == 2:
                assert count[0] == socket2[
                    0], f"socket id received in network query response is wrong for socket {iter} expected is {socket2[0]}"
                assert count[1] == socket2[
                    1], f"socket type received in network query response is wrong for socket {iter} expected is {socket2[1]}"
                assert count[2] == socket2[
                    2], f"source port received in network query response is wrong for socket {iter} expected is {socket2[2]}"
                assert count[3] == socket2[3], f"destination port received in network query response is wrong for " \
                                               f"socket {iter} expected is {socket2[3]} "
                assert count[4] == socket2[
                    4], f"server ip received in network query response is wrong for socket {iter} expected is {socket2[4]}"
            elif iter == 3:
                assert count[0] == socket3[
                    0], f"socket id received in network query response is wrong for socket {iter} expected is {socket3[0]}"
                assert count[1] == socket3[
                    1], f"socket type received in network query response is wrong for socket {iter} expected is {socket3[1]}"
                assert count[2] == socket3[
                    2], f"source port received in network query response is wrong for socket {iter} expected is {socket3[2]}"
                assert count[3] == socket3[3], f"destination port received in network query response is wrong for " \
                                               f"socket {iter} expected is {socket3[3]} "
                assert count[4] == socket3[
                    4], f"server ip received in network query response is wrong for socket {iter} expected is {socket3[4]} "

    # Close socket 1
    wifi_dut.interfaces.wifi.close_socket(sock)
    # Close socket 2
    wifi_dut.interfaces.wifi.close_socket(sock1)
    # Close socket 3
    wifi_dut.interfaces.wifi.close_socket(sock2)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
def test_query_wireless_stats_TC19175(wifi_sniffer, wifi_dut, wifi_access_point, logger):
    capture_filename = "test_query_wireless_stats_TC19175"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    # capture_filter = "ether host " + mac_address
    # wifi_sniffer.interfaces.capture.start_capture(
    #     capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
    #     )
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap"
        )
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    operating_mode, dtim_period, ideal_beacon_info, busy_beacon_info, beacon_interval = wifi_dut.interfaces.wifi.wlan_get_stats()
    wifi_sniffer.interfaces.capture.stop_capture()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    beacon_interval_ap, dtim_period_ap = get_beacon_interval(wifi_sniffer, decryption_key,
                                                             wifi_access_point.interfaces.wifi.ssid)

    logger.info(f"-------Beacon interval and DTIM period of the connected AP captured in the sniffer are-> beacon "
                f"interval:{beacon_interval_ap}, DTIM period:{dtim_period_ap}")

    beacon_interval_ap = beacon_interval_ap - (beacon_interval_ap % 100)

    assert operating_mode == 0, "Operating mode is not matching, expected is 0"
    assert beacon_interval == beacon_interval_ap, f"AP beacon interval received in wlan stats and actual beacon " \
                                                  f"interval of connected AP is not matched, e" \
                                                  f"xpected is {beacon_interval_ap}. But observed {beacon_interval} "
    assert dtim_period == dtim_period_ap, f"DTIM period received in wlan stats and actual DTIM " \
                                          f"interval of connected AP is not matched, e" \
                                          f"expected is {dtim_period_ap}. But observed {dtim_period} "


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
def test_query_wireless_stats_after_rejoin_TC19177(wifi_sniffer, wifi_dut, wifi_access_point, logger):
    capture_filename = "test_query_wireless_stats_after_rejoin_TC19177"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    # capture_filter = "ether host " + mac_address
    # wifi_sniffer.interfaces.capture.start_capture(
    #     capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
    #     )
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap"
        )
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wait_time = 5
    ApWirelessOff(wifi_access_point, wait_time, logger)

    operating_mode, dtim_period, ideal_beacon_info, busy_beacon_info, beacon_interval = wifi_dut.interfaces.wifi.wlan_get_stats()
    wifi_sniffer.interfaces.capture.stop_capture()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    beacon_interval_ap, dtim_period_ap = get_beacon_interval(wifi_sniffer, decryption_key,
                                                             wifi_access_point.interfaces.wifi.ssid)

    logger.info(f"-------Beacon interval and DTIM period of the connected AP captured in the sniffer are-> beacon "
                f"interval:{beacon_interval_ap}, DTIM period:{dtim_period_ap}")

    beacon_interval_ap = beacon_interval_ap - (beacon_interval_ap % 100)

    assert operating_mode == 0, "Operating mode is not matching, expected is 0"
    assert beacon_interval == beacon_interval_ap, f"AP beacon interval received in wlan stats and actual beacon " \
                                                  f"interval of connected AP is not matched, e" \
                                                  f"xpected is {beacon_interval_ap}. But observed {beacon_interval} "
    assert dtim_period == dtim_period_ap, f"DTIM period received in wlan stats and actual DTIM " \
                                          f"interval of connected AP is not matched, e" \
                                          f"expected is {dtim_period_ap}. But observed {dtim_period} "


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.SNTPClient,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_sntp__TC19191(
        wifi_sniffer, wifi_dut, wifi_access_point, logger
        ):
    capture_filename = "test_sntp__TC19191"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    sntp_server_address = wifi_dut.interfaces.wifi.get_sntp_server_ip()
    wifi_dut.interfaces.wifi.sntp_create(server_ip=sntp_server_address)
    time.sleep(10)
    asynchronous_request_time = 0
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=asynchronous_request_time)
    for event in events:
        if event.event_type == RS9116AsyncEventType.SNTP_EVENT:
            sntp_event = event.event_data
            asynchronous_request_time = event.timestamp + 1
        else:
            assert 1, f"SNTP asynchronous event is not received by DUT after connection request was sent to SNTP server"
    sntp_status = int(sntp_event.split(b":")[1])
    assert sntp_status == 1, "SNTP status received in asynchronous message for SNTP connection request is wrong " \
                             "expected is 1 "

    command_type, sntp_time = wifi_dut.interfaces.wifi.get_sntp_time()
    assert command_type == 2, "Command type received for the body of get_sntp_time response is wrong, expected is 2"
    command_type, sntp_date_time = wifi_dut.interfaces.wifi.get_sntp_timedate()
    assert command_type == 3, "Command type received for the body of get_sntp_timedate response is wrong, expected is 3"
    command_type, ip_version, server_ip = wifi_dut.interfaces.wifi.get_sntp_server_info()
    assert command_type == 6, "Command type received for the body of get_sntp_server_info response is wrong, expected " \
                              "is 6"
    assert ip_version == 4, "Ip version received for the body of get_sntp_server_info response is wrong, expected " \
                            "is 4"
    assert server_ip == sntp_server_address, f"SNTP server ip address received for the body of get_sntp_server_info " \
                                             f"response is wrong, expected " \
                                             "is {sntp_server_address}"

    wifi_dut.interfaces.wifi.sntp_delete()
    time.sleep(5)
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=asynchronous_request_time)
    for event in events:
        if event.event_type == RS9116AsyncEventType.SNTP_EVENT:
            sntp_event = event.event_data
        else:
            assert 1, f"SNTP asynchronous event is not received by DUT after SNTP delete is initiated"
    sntp_status = int(sntp_event.split(b":")[1])
    assert sntp_status == 1, "SNTP status received in asynchronous message for SNTP delete request is wrong expected " \
                             "is 1 "
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    ntp_capture_list = get_ntp_list(wifi_sniffer, decryption_key, ["ntp"])
    if not len(ntp_capture_list):
        logger.info(f"NTP packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")
    assert len(ntp_capture_list) > 0, f"NTP packets are not captured or one of the 4-way handshake pkts are not " \
                                      f"captured in the sniffer file "

    for ntp_pkt in ntp_capture_list:
        if (ntp_pkt[2] == sntp_server_address) and (ntp_pkt[3] == device_ip):
            logger.info(f"SNTP response body received in the sniffer {ntp_pkt}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_get_rtc_after_powersave_TC3945(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_ssl_three_sockets_send_data_testcaseTC3918"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    # The below API loads ca-cert into DUT at cert index 1
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                 cert_index=1,
                                                 )
    # The below API loads ca-cert into DUT at cert index 2
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                 cert_index=2,
                                                 )

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time = 100
    set_time_sec = ((set_minutes * 60) + set_seconds)

    # This API starts RTC timer in DUT
    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)
    logger.info(f"wait for {wait_time} seconds")
    time.sleep(wait_time)

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec

    assert (time_dif - wait_time) == 0, "get time is not updated"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "features": RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        },
    )
def test_wifi_wireless_statistics_AP_TC19176(wifi_ap_dut, wifi_client):
    wifi_client.interfaces.wifi.join()
    assert wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip) < 0.1
    operating_mode, dtim_period, ideal_beacon_info, busy_beacon_info, beacon_interval = wifi_ap_dut.interfaces.wifi.wlan_get_stats()
    assert operating_mode == 6, "Operating mode is not matching, expected is 6"
