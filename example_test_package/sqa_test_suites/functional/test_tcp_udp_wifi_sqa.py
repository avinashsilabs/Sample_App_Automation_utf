import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks tcp close functionality
def test_wifi_tcp_close_testcase1(wifi_dut, wifi_access_point, remote_socket):
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
    # Open tcp socket in remote device(Raspberry pi or static device)
    remote_socket.interfaces.socket.start_server()
    # DUT opens tcp client socket
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    assert sock == 0
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(5001, device_ip, socket_id=sock)
    # tcp socket opened in DUT connects to the tcp server
    wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    # DUT sends 50 bytes of data over tcp socket
    wifi_dut.interfaces.wifi.send(sock, 50)
    # DUT closes the tcp socket
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks data receive functionality over tcp socket
def test_wifi_tcp_data_receive_check_testcase14(wifi_dut, wifi_access_point, remote_socket):
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

    remote_socket.interfaces.socket.start_server()
    # DUT opens tcp client socket
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    assert sock == 0
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(5001, device_ip, socket_id=sock)
    # tcp socket opened in DUT connects to the tcp server
    wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)

    tx_buffer = "12345678901234567890123456789012345678901234567890"
    buffer_length = len(tx_buffer)
    # send 50 bytes of data from tcp server opened remotely
    remote_socket.interfaces.socket.send_data_tcp(tx_buffer)
    # DUT receives data over tcp socket after execution of below api
    buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock, data_len=buffer_length)
    assert buffer_length == buffer_length_rx, "buffer length sent and received is not matched"
    assert tx_buffer.encode() == buffer_rx, "contents of data sent and receive are not matched"
    # DUT closes the tcp socket
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket in the dut"
    remote_socket.interfaces.socket.socket_close_indication(1)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks udp socket close functionality
def test_wifi_udp_close_testcase2(wifi_dut, wifi_access_point, remote_socket):
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
    # Open UDP socket remotely
    remote_socket.interfaces.socket.start_server(socket_type=1)
    # Open UDP socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
    assert sock == 0, "socket id received is not matched. Expected is 0"
    # DUT binds to socket(device_ip, 5001)
    wifi_dut.interfaces.wifi.bind(5001, device_ip, socket_id=sock)
    # DUT sends data over udp socket
    wifi_dut.interfaces.wifi.send_to(sock, 50, remote_socket.interfaces.socket.server_ip,
                                     remote_socket.interfaces.socket.server_port)
    # DUT closes the socket.socket id is mentioned in sock variable
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "Unable to close the udp socket"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks data receive functionality over udp socket
def test_wifi_udp_receive_testcase15(wifi_dut, wifi_access_point, remote_socket):
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

    # Open UDP socket remotely
    remote_socket.interfaces.socket.start_server(socket_type=1)
    # Open UDP socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
    assert sock == 0, "socket id received is not matched. Expected is 0"
    # DUT binds to socket(device_ip, 5001)
    wifi_dut.interfaces.wifi.bind(5001, device_ip, socket_id=sock)
    tx_buffer = "12345678901234567890123456789012345678901234567890"
    buffer_length = len(tx_buffer)
    # send 50 bytes of data from udp socket opened remotely
    remote_socket.interfaces.socket.send_data_udp(tx_buffer, device_ip, port=5001)
    # DUT receives data over udp socket after execution of below api
    buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock, data_len=buffer_length)
    assert buffer_length == buffer_length_rx, "buffer length sent and received is not matched"
    assert tx_buffer.encode() == buffer_rx, "contents of data sent and receive are not matched"
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close udp socket opened in the dut"
