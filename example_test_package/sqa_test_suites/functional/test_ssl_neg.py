import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    SocketOptions,
    SocketType,
    Cipher,
    )

from utf.interfaces.wifi import WlanError
from utf.utils.subprocess_manager import SubprocessManager

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Load ssl certificates in the DUT
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Create a new TCP/IP socket over ssl 
        6. Bind the socket with DUT ip address
        7. Connect the client with server socket as specified port number.
        8. Check whether DUT is throwing the error as per the test case specified 
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""


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
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
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
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_0_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    result = wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
    assert b"success" not in result, f"DUT successfully connected to server even though ssl version is mismatched"
    error_code = result.split(b":")[1].strip().decode()
    assert error_code == '0xD2', "Observed wrong error code, expected is 0xD2"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_client_ciphersuite_mismatch_testcase139(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    ssl_server.interfaces.ssl.config['no_of_pkts']
    ssl_server.interfaces.ssl.config['buffer_length']
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
    wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=Cipher.BIT_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)
    ssl_server.interfaces.ssl.start_server(cipher_list="ECDHE-RSA-AES256-SHA384")
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    result = wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
    assert b"success" not in result, f"DUT successfully connected to server even though cipher list is mismatched"
    error_code = result.split(b":")[1].strip().decode()
    assert error_code == '0xD2', "Observed wrong error code, expected is 0xD2"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
def test_ssl_server_no_server_cert_testcase3(
        wifi_dut, wifi_access_point, ssl_client, logger
        ):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()

    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLServerCertificate,
                                               cert_index=0
                                               )
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLServerPrivateKey,
                                               cert_index=0
                                               )
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

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


# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#         "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
#         "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
#         "rejoin_max_retry": 10,
#         "scan_interval": 6,
#         "beacon_missed_count": 40,
#         "first_time_retry": 0,
#         "ca_cert": "ca-chain.cert.pem"
#         }
#     )
# @pytest.mark.start_state("wifi_dut", wifi= ['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# def test_ssl_server_connect_non_ssl_client_testcase4(
#         wifi_dut, wifi_access_point, logger
#         ):
#     # DUT connects to AP after join_ap API is executed
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     # DUT gets ipaddress through DHCP process after start_ip API is executed
#     wifi_dut.interfaces.wifi.start_ip()
#     # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
#     # DUT to power save in Wifi+bluetooth mode
#     wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
#     wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
#     # The below api parses DUTs IP address
#     device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
#
#     # The below api opens ssl server socket in the DUT
#     sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
#     assert sock == 0,  f"socket id received is wrong, expected is 0"
#     # Socket binds at (device_ip, 5001) in DUT
#     wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
#     wifi_dut.interfaces.wifi.listen(sock, backlog=1)
#     # Connect from third party device to the socket opened in the DUT
#     SubprocessManager.simple_execute(f"iperf -c {device_ip} -p 5001 -t 10")
#     with pytest.raises(WlanError) as exc_info:
#         wifi_dut.interfaces.wifi.accept(sock)
#     assert exc_info.value.error_code == 0xFFFFFFFF, "DUT sent wrong error code, expected is 0xFFFFFFFF"
#

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
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
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
def test_ssl_server_1_0version_client_1_2_testcase7(
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
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE_VERSION_1_0)
    assert sock == 0

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
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
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
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
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5001)

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
    assert sock == 1, f"socket id received is wrong, expected is 1"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5002)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5002)

    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
    assert sock == 2, f"socket id received is wrong, expected is 2"

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5003)

    # ssl socket opened in DUT connects to the server
    result = wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5003)
    assert b"success" not in result, f"DUT successfully connected to server even though ssl version is mismatched"
    error_code = result.split(b":")[1].strip().decode()
    assert error_code == '0xD3', "Observed wrong error code, expected is 0xD3"


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
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
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
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
    # ssl socket opened in DUT connects to the server
    result = wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5001)
    assert b"success" not in result, f"DUT successfully connected to server even though ssl version is mismatched"
    error_code = result.split(b":")[1].strip().decode()
    assert error_code == '0xD3', "Observed wrong error code, expected is 0xD3"
