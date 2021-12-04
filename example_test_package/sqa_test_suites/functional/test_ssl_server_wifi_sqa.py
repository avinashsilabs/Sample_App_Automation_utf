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
    Cipher,
    )
import string
import random
from interfaces.wifi import WlanError
from threading import Thread
from utils import get_tls_certificate_dir
from utils.stopwatch import Stopwatch


# Mark all tests in this module with 'framework_integration_test'

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
        "server_cert": "mosquitto-utf.silabs.com.cert.pem",
        "server_key": "mosquitto-utf.silabs.com.key.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
def test_ssl_server_socket_close_testcase18(
        wifi_dut, wifi_access_point, ssl_client, logger
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

    for count in range(0, 2):
        # The below api opens ssl server socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
        assert sock == 0, f"socket id received is wrong, expected is 0 on iteration {count}"
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
        "server_cert": "mosquitto-utf.silabs.com.cert.pem",
        "server_key": "mosquitto-utf.silabs.com.key.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
def test_ssl_server_testcase2(
        wifi_dut, wifi_access_point, ssl_client, logger
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

    # The below api opens ssl server socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
    assert sock == 0
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
    assert b"success" in result, "unable to close opened tcp socket"
    assert data_sent == data_receive.decode(), "data length sent and received is not matching"


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
        "server_cert": "mosquitto-utf.silabs.com.cert.pem",
        "server_key": "mosquitto-utf.silabs.com.key.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
def test_ssl_server_1_2_version_testcase6(
        wifi_dut, wifi_access_point, ssl_client, logger
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

    # The below api opens ssl server socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE_VERSION_1_2)
    assert sock == 0
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
    wifi_dut.interfaces.wifi.listen(sock, backlog=1)
    # Connect from third party device to the socket opened in the DUT
    ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001, version="ssl_1.2")
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
    assert b"success" in result, "unable to close opened tcp socket"
    assert data_sent == data_receive.decode(), "data length sent and received is not matching"



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
        "server_cert": "mosquitto-utf.silabs.com.cert.pem",
        "server_key": "mosquitto-utf.silabs.com.key.pem"
        }
    )
@pytest.mark.parametrize("cipher_list", [
    [Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA256, Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA256,
     Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA, Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA]])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
def test_ssl_server_diff_cipher_suite_testcase137(
        wifi_dut, wifi_access_point, ssl_client, logger, cipher_list
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
        assert sock == 0
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
