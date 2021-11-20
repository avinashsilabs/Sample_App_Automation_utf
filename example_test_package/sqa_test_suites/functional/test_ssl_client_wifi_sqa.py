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
    SocketOptions,
    SocketType,
    )
import string
import random
from interfaces.wifi import WlanError
from threading import Thread


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
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_client_testcase1(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # The api returns 100 bytes of random data
    data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    data_length = len(data_sent)
    # DUT sends 100 bytes of data over ssl socket
    wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
    server_socket_no = 1
    # SSL server receives the data over ssl socket
    data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
    assert data_sent == data_receive.decode(), "data length sent and received is not matching"

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
def test_ssl_client_version_1_2_testcase10(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(version="ssl_1.2")
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE_VERSION_1_2)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_2_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # The api returns 100 bytes of random data
    data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    data_length = len(data_sent)
    # DUT sends 100 bytes of data over ssl socket
    wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
    server_socket_no = 1
    # SSL server receives the data over ssl socket
    data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
    assert data_sent == data_receive.decode(), "data length sent and received is not matching"

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
def test_ssl_client_version_1_0_server_version_1_2_testcase11(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(version="ssl_1.2")

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE_VERSION_1_0)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_0_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)

    # ssl socket opened in DUT connects to the server
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl)
    assert exc_info.value.error_code == 0x00D2, "DUT sent wrong error code, expected is 0x00D2"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.parametrize("repeat", 5)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
def test_ssl_client_connect_close_sequence_testcase133(
        wifi_dut, wifi_access_point, ssl_server, logger, repeat
        ):
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    for iteration in range(0, repeat):
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server()
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

        # The api returns 100 bytes of random data
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        # DUT sends 100 bytes of data over ssl socket
        wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
        server_socket_no = 1
        # SSL server receives the data over ssl socket
        data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
        assert data_sent == data_receive.decode(), "data length sent and received is not matching"
        # Close socket 1
        wifi_dut.interfaces.wifi.close_socket(sock)
        time.sleep(1)
        ssl_server.interfaces.ssl.stop_server()



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
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_client_tx_rx_bidirectional_testcase131(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    ssl_server.interfaces.ssl.start_server(port=port2)
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                           socket_flag=SocketType.ASYNCHRONOUS)
    assert sock == 0

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE)
    assert sock1 == 1

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port2, device_ip, socket_id=sock1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

    # pkt_count = 1000
    ssl_server.interfaces.ssl.send_data(1, pkt_count, msg_length=buffer_length)
    ssl_server.interfaces.ssl.data_receive(2, pkt_count, buffer_length)
    wifi_dut.interfaces.wifi.send_data_pkts(sock1, buffer_length, pkt_count)
    time.sleep(120)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
    bytes_received = int(result.split(b":")[1])
    logger.info(f"bytes received on socket {sock} -> {bytes_received}")
    assert bytes_received == (pkt_count * buffer_length), "Packet loss observed while receive test"
    wifi_dut.interfaces.wifi.close_socket(sock)
    wifi_dut.interfaces.wifi.close_socket(sock1)


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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 40,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_client_tx_rejoin_length_1460_testcase145(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    ssl_server.interfaces.ssl.data_receive(1, pkt_count, buffer_length, pkt_rcv_timeout=120)
    thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 20, logger), )
    thread.start()
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count, timeout=600)

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
        "rejoin_max_retry": 40,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_client_tx_rejoin_length_20_testcase145(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    buffer_length = 20
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Set the tcp max retry for the socket
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    ssl_server.interfaces.ssl.data_receive(1, pkt_count, buffer_length, pkt_rcv_timeout=120)
    thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 20, logger), )
    thread.start()
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count, timeout=300)

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
        "rejoin_max_retry": 40,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_client_rx_while_rejoining_testcase146(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                           socket_flag=SocketType.ASYNCHRONOUS)
    assert sock == 0

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Set the tcp max retry for the socket
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(port1, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    ssl_server.interfaces.ssl.send_data(1, pkt_count, msg_length=buffer_length)
    thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 20, logger), )
    thread.start()
    time.sleep(300)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
    bytes_received = int(result.split(b":")[1])
    logger.info(f"bytes received on socket {sock} -> {bytes_received}")
    assert bytes_received == (pkt_count * buffer_length), "Packet loss observed while receive test"
    wifi_dut.interfaces.wifi.close_socket(sock)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.Disabled,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_socket_limit_testcase15(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=5002)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=5003)

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(5001, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5001)

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
    assert sock == 1
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(5002, device_ip, socket_id=sock)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5002)

    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
    assert sock == 2

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(5003, device_ip, socket_id=sock)
    with pytest.raises(WlanError) as exc_info:
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5003)
    assert exc_info.value.error_code == 0x00d3, "observed wrong error code, expected is 0x00d3"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.Disabled,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.HTTPSServer | RS9116TCPIPFeatureBitMap.SingleSSLSocket,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_socket_limit_select_testcase65(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl server socket in remote device(Raspberry pi or static device)

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
    assert sock == 0
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(5001, device_ip, socket_id=sock)
    with pytest.raises(WlanError) as exc_info:
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5001)
    assert exc_info.value.error_code == 0x00d3, "observed wrong error code, expected is 0x00d3"
