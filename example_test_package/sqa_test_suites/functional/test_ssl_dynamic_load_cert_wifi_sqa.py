import time
import pytest
from devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116PowerSaveModes,
    SocketOptions
    )
from interfaces.wifi import WlanError
from utils import get_tls_certificate_dir


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                             ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_dynamic_load_cert_no_index_testcase1(
        wifi_dut, wifi_access_point, ssl_server, logger, cert1
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']

    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1]
        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
    # Close socket 1
    wifi_dut.interfaces.wifi.close_socket(sock)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                             ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_dynamic_load_cert_socket_connected_state_testcase2(
        wifi_dut, wifi_access_point, ssl_server, logger, cert1
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']

    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    with pytest.raises(WlanError) as exc_info:
        # The below API loads ca-cert into DUT
        # The below API loads ca-cert into DUT at cert index 0
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                     cert_index=0,
                                                     )
    assert ((exc_info.value.error_code == 0x5d) or (exc_info.value.error_code == 0x5e)), "observed wrong error code, " \
                                                                                         "expected is 0x5d or 0x5e "


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                             ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_dynamic_load_new_cert_testcase3(
        wifi_dut, wifi_access_point, ssl_server, logger, cert1
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']

    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1]
        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
    # Close socket 1
    wifi_dut.interfaces.wifi.close_socket(sock)
    # The below API clears ca-cert
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                               cert_index=0
                                               )
    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.Disabled,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
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
def test_dynamic_load_three_ssl_sockets_testcase4(
        wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
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
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX1)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port2, device_ip, socket_id=sock1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

    # Open ssl client socket in the DUT
    sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock2 == 2

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX2)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port3, device_ip, socket_id=sock2)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1, 2, 3]
        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
    wifi_dut.interfaces.wifi.send_data_pkts(sock1, buffer_length, pkt_count)
    wifi_dut.interfaces.wifi.send_data_pkts(sock2, buffer_length, pkt_count)

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
        "coex_mode": RS9116CoexMode.Disabled,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_dynamic_load_three_ssl_sockets_multiple_iterations_testcase6(
        wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
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
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX1)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port2, device_ip, socket_id=sock1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

    # Open ssl client socket in the DUT
    sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock2 == 2

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX2)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port3, device_ip, socket_id=sock2)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1, 2, 3]
        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
    wifi_dut.interfaces.wifi.send_data_pkts(sock1, buffer_length, pkt_count)
    wifi_dut.interfaces.wifi.send_data_pkts(sock2, buffer_length, pkt_count)

    # Close socket 1
    wifi_dut.interfaces.wifi.close_socket(sock)
    # Close socket 2
    wifi_dut.interfaces.wifi.close_socket(sock1)
    # Close socket 3
    wifi_dut.interfaces.wifi.close_socket(sock2)
    # The below API clears ca-cert at index0 in the dut
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                               cert_index=0
                                               )
    # The below API clears ca-cert at index1 in the dut
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                               cert_index=1
                                               )
    # The below API clears ca-cert at index2 in the dut
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                               cert_index=2
                                               )
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


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.Disabled,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_dynamic_load_three_ssl_sockets_multiple_iterations_not_erase_cert_testcase7(
        wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
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
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX1)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port2, device_ip, socket_id=sock1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

    # Open ssl client socket in the DUT
    sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock2 == 2

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX2)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port3, device_ip, socket_id=sock2)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1, 2, 3]
        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
    wifi_dut.interfaces.wifi.send_data_pkts(sock1, buffer_length, pkt_count)
    wifi_dut.interfaces.wifi.send_data_pkts(sock2, buffer_length, pkt_count)

    # Close socket 1
    wifi_dut.interfaces.wifi.close_socket(sock)
    # Close socket 2
    wifi_dut.interfaces.wifi.close_socket(sock1)
    # Close socket 3
    wifi_dut.interfaces.wifi.close_socket(sock2)
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


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.Disabled,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_dynamic_load_powersave_not_enabled_testcase9(
        wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
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
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX1)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port2, device_ip, socket_id=sock1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

    # Open ssl client socket in the DUT
    sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock2 == 2

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX2)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port3, device_ip, socket_id=sock2)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1, 2, 3]
        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
    wifi_dut.interfaces.wifi.send_data_pkts(sock1, buffer_length, pkt_count)
    wifi_dut.interfaces.wifi.send_data_pkts(sock2, buffer_length, pkt_count)

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
        "coex_mode": RS9116CoexMode.Disabled,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_dynamic_load_powersave_enabled_testcase14(
        wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):

    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
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
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX1)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port2, device_ip, socket_id=sock1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

    # Open ssl client socket in the DUT
    sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock2 == 2

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX2)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port3, device_ip, socket_id=sock2)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1, 2, 3]
        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
    wifi_dut.interfaces.wifi.send_data_pkts(sock1, buffer_length, pkt_count)
    wifi_dut.interfaces.wifi.send_data_pkts(sock2, buffer_length, pkt_count)

    # Close socket 1
    wifi_dut.interfaces.wifi.close_socket(sock)
    # Close socket 2
    wifi_dut.interfaces.wifi.close_socket(sock1)
    # Close socket 3
    wifi_dut.interfaces.wifi.close_socket(sock2)



# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.Disabled,
#         "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#         "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
#         "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
#         "rejoin_max_retry": 10,
#         "scan_interval": 6,
#         "beacon_missed_count": 40,
#         "first_time_retry": 0,
#         }
#     )
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
#                              ]
#                          )
# @pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_store_config"])
# def test_dynamic_load_auto_join_testcase8(
#         wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
#         ):
#     pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
#     buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
#     port1 = ssl_server.interfaces.ssl.config['device_port1']
#     port2 = ssl_server.interfaces.ssl.config['device_port2']
#     port3 = ssl_server.interfaces.ssl.config['device_port3']
#     # DUT connects to AP after join_ap API is executed
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     # DUT gets ipaddress through DHCP process after start_ip API is executed,
#     wifi_dut.interfaces.wifi.start_ip()
#     # The below api parses DUTs IP address
#     device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
#
#     wifi_dut.interfaces.wifi.config_save()
#     wifi_dut.interfaces.wifi.config_enable(config=1)
#     wifi_dut.interfaces.wifi.reset_soft()
#     wifi_dut.interfaces.wifi.wireless_init()
#     time.sleep(10)
#
#     # The below API loads ca-cert into DUT at cert index 0
#     wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
#                                                  str(get_tls_certificate_dir().joinpath(cert1[0])),
#                                                  cert_index=0,
#                                                  )
#     # The below API loads ca-cert into DUT at cert index 1
#     wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
#                                                  str(get_tls_certificate_dir().joinpath(cert2[0])),
#                                                  cert_index=1,
#                                                  )
#     # The below API loads ca-cert into DUT at cert index 2
#     wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
#                                                  str(get_tls_certificate_dir().joinpath(cert3[0])),
#                                                  cert_index=2,
#                                                  )
#
#     # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
#     # DUT to power save in Wifi+bluetooth mode
#     wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
#     wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
#
#     # Open ssl server socket in remote device(Raspberry pi or static device)
#     ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
#     # Open ssl server socket in remote device(Raspberry pi or static device)
#     ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
#     # Open ssl server socket in remote device(Raspberry pi or static device)
#     ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
#
#     # Open ssl client socket in the DUT
#     sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
#     assert sock == 0
#     # Enable ssl option for socket opened
#     wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
#                                                SocketOptions.SSL_ENABLE)
#     # Enable cert index 0 for socket opened
#     wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
#                                                SocketOptions.CERT_INDEX0)
#     # Socket binds at (device_ip, 5001) in DUT
#     wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
#     # ssl socket opened in DUT connects to the server
#     wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
#
#     # Open ssl client socket in the DUT
#     sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
#     assert sock1 == 1
#     # Enable ssl option for socket opened
#     wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
#                                                SocketOptions.SSL_ENABLE)
#     # Enable cert index 1 for socket opened
#     wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
#                                                SocketOptions.CERT_INDEX1)
#     # Socket binds at (device_ip, 5001) in DUT
#     wifi_dut.interfaces.wifi.bind(port2, device_ip, socket_id=sock1)
#     # ssl socket opened in DUT connects to the server
#     wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)
#
#     # Open ssl client socket in the DUT
#     sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
#     assert sock2 == 2
#
#     # Enable ssl option for socket opened
#     wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
#                                                SocketOptions.SSL_ENABLE)
#     # Enable cert index 1 for socket opened
#     wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
#                                                SocketOptions.CERT_INDEX2)
#
#     # Socket binds at (device_ip, 5001) in DUT
#     wifi_dut.interfaces.wifi.bind(port3, device_ip, socket_id=sock2)
#     # ssl socket opened in DUT connects to the server
#     wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
#
#     if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
#         socket_no = [1, 2, 3]
#         for socket in socket_no:
#             ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
#     wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
#     wifi_dut.interfaces.wifi.send_data_pkts(sock1, buffer_length, pkt_count)
#     wifi_dut.interfaces.wifi.send_data_pkts(sock2, buffer_length, pkt_count)
#
#     # Close socket 1
#     wifi_dut.interfaces.wifi.close_socket(sock)
#     # Close socket 2
#     wifi_dut.interfaces.wifi.close_socket(sock1)
#     # Close socket 3
#     wifi_dut.interfaces.wifi.close_socket(sock2)