# Test author: Vinod.G
# Test suite: Multicast test suite
import time
import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, DeviceConstants, SocketParams, \
    MulticastParams

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Association to Third party AP
        3. Get the ip address through DHCP
        4. Add multicast address to the multicast group
        5. Open multicast UDP socket
        6. Receive data on the socket. Verify the data integrity checks
      
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""


def dut_connect_get_ip(wifi_dut, wifi_access_point):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "rejoin_max_retry": 10,
            "scan_interval": 6,
            "beacon_missed_count": 40,
            "first_time_retry": 0,
            }
        )
    ]


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_multicast_receive_TC3767(wifi_dut, wifi_access_point, multicast_client, logger):
    dut_connect_get_ip(wifi_dut, wifi_access_point)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
    wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
    socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
    assert socket_id == 0, f"socket id received is wrong, expected is 0"
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

    multicast_client.interfaces.multicast.start_server()

    multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
    multicast_client.interfaces.multicast.socket_close()
    time.sleep(30)
    wifi_dut.interfaces.wifi.close_socket(socket_id)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)
    bytes_received = int(result.split(b":")[1])
    bytes_sent = (no_of_pkts * buffer_length)
    packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)
    logger.info(f"Packet loss {packet_loss}")
    assert packet_loss < 20, "Packet loss is not in tolerance level"


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_multicast_group_leave_TC3768(wifi_dut, wifi_access_point, multicast_client, logger):
    dut_connect_get_ip(wifi_dut, wifi_access_point)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

    for count in range(0, 3):
        if count % 2 == 0:
            wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
        else:
            wifi_dut.interfaces.wifi.leave_multicast_group(ip_version, multicast_ip)
        socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
        assert socket_id == 0, f"socket id received is wrong, expected is 0"
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)
        multicast_client.interfaces.multicast.start_server()

        multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
        multicast_client.interfaces.multicast.socket_close()
        time.sleep(30)
        wifi_dut.interfaces.wifi.close_socket(socket_id)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)

        bytes_received = int(result.split(b":")[1])
        bytes_sent = (no_of_pkts * buffer_length)
        packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)

        if count % 2 == 0:
            logger.info(f"Packet loss {packet_loss}")
            assert packet_loss < 20, "Packet loss is not in tolerance level"
        else:
            assert bytes_received == 0, "Data received on multicast socket even though device is left from multicast " \
                                        "group "


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_multicast_filter_select_all_TC3770(wifi_dut, wifi_access_point, multicast_client, logger):
    dut_connect_get_ip(wifi_dut, wifi_access_point)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

    wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_SET_ALL, multicast_mac)

    wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
    socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
    assert socket_id == 0, f"socket id received is wrong, expected is 0"
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

    multicast_client.interfaces.multicast.start_server()

    multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
    multicast_client.interfaces.multicast.socket_close()
    time.sleep(30)
    wifi_dut.interfaces.wifi.close_socket(socket_id)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)

    bytes_received = int(result.split(b":")[1])
    bytes_sent = (no_of_pkts * buffer_length)
    packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)
    logger.info(f"Packet loss {packet_loss}")
    assert packet_loss < 20, "Packet loss is not in tolerance level"


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_multicast_filter_clear_all_TC3771(wifi_dut, wifi_access_point, multicast_client, logger):
    dut_connect_get_ip(wifi_dut, wifi_access_point)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

    wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_CLEAR_AL, multicast_mac)

    wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
    socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
    assert socket_id == 0, f"socket id received is wrong, expected is 0"
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

    multicast_client.interfaces.multicast.start_server()
    multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
    multicast_client.interfaces.multicast.socket_close()
    time.sleep(30)
    wifi_dut.interfaces.wifi.close_socket(socket_id)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)

    bytes_received = int(result.split(b":")[1])
    assert bytes_received == 0, "Data received on multicast socket even though multicast_filter_clear_all is selected "


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_multicast_filter_clear_specific_TC3772(wifi_dut, wifi_access_point, multicast_client, logger):
    dut_connect_get_ip(wifi_dut, wifi_access_point)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

    for count in range(0, 2):
        if count == 1:
            wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_CLEAR_BIT, multicast_mac)

        wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
        socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
        assert socket_id == 0, f"socket id received is wrong, expected is 0"
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

        multicast_client.interfaces.multicast.start_server()

        multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
        multicast_client.interfaces.multicast.socket_close()
        time.sleep(30)
        wifi_dut.interfaces.wifi.close_socket(socket_id)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)

        bytes_received = int(result.split(b":")[1])
        bytes_sent = (no_of_pkts * buffer_length)
        packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)
        if count == 0:
            logger.info(f"Packet loss {packet_loss}")
            assert packet_loss < 20, "Packet loss is not in tolerance level"
        else:
            assert bytes_received == 0, "Data received on multicast socket even though the multicast address is " \
                                        "removed from the multicast group"


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_multicast_filter_add_specific_TC3773(wifi_dut, wifi_access_point, multicast_client, logger):
    dut_connect_get_ip(wifi_dut, wifi_access_point)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

    for count in range(0, 2):
        if count == 0:
            wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_CLEAR_AL, multicast_mac)
        else:
            wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_ADD_BIT, multicast_mac)

        wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
        socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
        assert socket_id == 0, f"socket id received is wrong, expected is 0"
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

        multicast_client.interfaces.multicast.start_server()

        multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
        multicast_client.interfaces.multicast.socket_close()
        time.sleep(30)
        wifi_dut.interfaces.wifi.close_socket(socket_id)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)

        bytes_received = int(result.split(b":")[1])
        bytes_sent = (no_of_pkts * buffer_length)
        packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)

        if count == 0:
            assert bytes_received == 0, "Data received on multicast socket even though multicast_filter_clear_all is " \
                                        "selected "
        else:
            logger.info(f"Packet loss {packet_loss}")
            assert packet_loss < 20, "Packet loss is not in tolerance level"
