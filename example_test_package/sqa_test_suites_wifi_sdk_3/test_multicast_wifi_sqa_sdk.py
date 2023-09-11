import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    SocketParams,
    MulticastParams
)

"""The testcases added in this file run below test steps for DUT-Si91x
        1. Configuration of DUT in 2G/5G : BGN
        2. Association to Third party AP
        3. Get the ip address through DHCP
        4. Add multicast address to the multicast group
        5. Open multicast UDP socket
        6. Receive data on the socket. Verify the data integrity checks

    setup requirement:
        1. DUT(Si91x)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
        }
    )
]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "multicast_leave", "disassociated"])
def test_wifi_sdk_multicast_receive_TC19369(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client, logger,
                                            sl_collections):
    try:
        capture_filename = "test_wifi_sdk_multicast_receive_TC19369"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
        logger.info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.join_multicast_address(interface="client", multicast_address=multicast_ip)

        logger.info("Opening UDP client socket in DUT")
        socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
        assert socket_id == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"socket id received is {socket_id} which is expected")
        wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

        logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
        multicast_client.interfaces.multicast.start_server()

        logger.info(
            f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
        multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
        multicast_client.interfaces.multicast.socket_close()
        time.sleep(30)
        logger.info(f"Closing socket_id->{socket_id}")
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{socket_id}"
        logger.info(f"Successfully closed socket_id->{socket_id}")

        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)
        bytes_received = int(result.split(b":")[1])
        bytes_sent = (no_of_pkts * buffer_length)
        packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)
        logger.info(f"Packet loss {packet_loss}")
        assert packet_loss < 20, "Packet loss is not in tolerance level"

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
        igmp_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ['igmp'],
                                                         capture_filename, ap_bssid)
        assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
                             "disassociated"])
def test_wifi_sdk_multicast_group_leave_TC19370(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client, logger,
                                                sl_collections):
    try:
        capture_filename = "test_wifi_sdk_multicast_group_leave_TC19370"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
        for count in range(0, 3):
            if count % 2 == 0:
                logger.info(f"DUT joining to the multicast group {multicast_ip}")
                wifi_dut.interfaces.wifi.join_multicast_address(interface="client", multicast_address=multicast_ip)
            else:
                wifi_dut.interfaces.wifi.leave_multicast_address(interface="client", multicast_address=multicast_ip)

            socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
            assert socket_id == 0, f"socket id received is wrong, expected is 0"
            logger.info(f"socket id received is {socket_id} which is expected")
            wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

            logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
            multicast_client.interfaces.multicast.start_server()

            logger.info(
                f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
            multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
            multicast_client.interfaces.multicast.socket_close()
            time.sleep(30)
            logger.info(f"Closing socket_id->{socket_id}")
            result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
            assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{socket_id}"
            logger.info(f"Successfully closed socket_id->{socket_id}")

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
                logger.info(
                    "No data is received by DUT on multicast socket when the device is left from multicast group "
                    "which is expected")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        igmp_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ['igmp'],
                                                         capture_filename, ap_bssid)
        assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
                             "disassociated"])
def test_wifi_sdk_multicast_filter_select_all_TC19372(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client,
                                                      logger, sl_collections):
    try:
        capture_filename = "test_wifi_sdk_multicast_filter_select_all_TC19372"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
        wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_SET_ALL, multicast_mac)

        logger.info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.join_multicast_address(interface="client", multicast_address=multicast_ip)
        socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
        assert socket_id == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"socket id received is {socket_id} which is expected")
        wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

        logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
        multicast_client.interfaces.multicast.start_server()

        logger.info(
            f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
        multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
        multicast_client.interfaces.multicast.socket_close()
        time.sleep(30)
        logger.info(f"Closing socket_id->{socket_id}")
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{socket_id}"
        logger.info(f"Successfully closed socket_id->{socket_id}")

        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)
        bytes_received = int(result.split(b":")[1])
        bytes_sent = (no_of_pkts * buffer_length)
        packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)
        logger.info(f"Packet loss {packet_loss}")
        assert packet_loss < 20, "Packet loss is not in tolerance level"

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        igmp_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ['igmp'],
                                                         capture_filename, ap_bssid)
        assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
                             "disassociated"])
def test_wifi_sdk_multicast_filter_clear_all_TC19373(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client,
                                                     logger, sl_collections):
    try:
        capture_filename = "test_wifi_sdk_multicast_filter_clear_all_TC19373"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
        wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_CLEAR_AL, multicast_mac)

        logger.info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.join_multicast_address(interface="client", multicast_address=multicast_ip)
        socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
        assert socket_id == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"socket id received is {socket_id} which is expected")
        wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

        logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
        multicast_client.interfaces.multicast.start_server()

        logger.info(
            f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
        multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
        multicast_client.interfaces.multicast.socket_close()
        time.sleep(30)
        logger.info(f"Closing socket_id->{socket_id}")
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{socket_id}"
        logger.info(f"Successfully closed socket_id->{socket_id}")

        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)
        bytes_received = int(result.split(b":")[1])
        assert bytes_received == 0, "Data received on multicast socket even though multicast_filter_clear_all is selected "
        logger.info(
            "Data is not received on multicast socket when multicast_filter_clear_all filter is selected which is "
            "expected")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        igmp_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ['igmp'],
                                                         capture_filename, ap_bssid)
        assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
                             "disassociated"])
def test_wifi_sdk_multicast_filter_clear_specific_TC19374(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client,
                                                          logger, sl_collections):
    try:
        capture_filename = "test_wifi_sdk_multicast_filter_clear_specific_TC19374"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
        for count in range(0, 2):
            if count == 1:
                wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_CLEAR_BIT, multicast_mac)
            logger.info(f"DUT joining to the multicast group {multicast_ip}")
            wifi_dut.interfaces.wifi.join_multicast_address(interface="client", multicast_address=multicast_ip)
            socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
            assert socket_id == 0, f"socket id received is wrong, expected is 0"
            logger.info(f"socket id received is {socket_id} which is expected")
            wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

            logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
            multicast_client.interfaces.multicast.start_server()

            logger.info(
                f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
            multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
            multicast_client.interfaces.multicast.socket_close()
            time.sleep(30)
            logger.info(f"Closing socket_id->{socket_id}")
            result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
            assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{socket_id}"
            logger.info(f"Successfully closed socket_id->{socket_id}")

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
            logger.info("Data is not received on multicast socket when the multicast address is removed from the "
                        "multicast group which is expected")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        igmp_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ['igmp'],
                                                         capture_filename, ap_bssid)
        assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
                             "disassociated"])
def test_wifi_sdk_multicast_filter_add_specific_TC19375(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client,
                                                        logger, sl_collections):
    try:
        capture_filename = "test_wifi_sdk_multicast_filter_add_specific_TC19375"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
        for count in range(0, 2):
            if count == 0:
                wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_CLEAR_AL, multicast_mac)
            else:
                wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_ADD_BIT, multicast_mac)
            logger.info(f"DUT joining to the multicast group {multicast_ip}")
            wifi_dut.interfaces.wifi.join_multicast_address(interface="client", multicast_address=multicast_ip)
            socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
            assert socket_id == 0, f"socket id received is wrong, expected is 0"
            logger.info(f"socket id received is {socket_id} which is expected")
            wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

            logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
            multicast_client.interfaces.multicast.start_server()

            logger.info(
                f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
            multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
            multicast_client.interfaces.multicast.socket_close()
            time.sleep(30)

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

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        igmp_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ['igmp'],
                                                         capture_filename, ap_bssid)
        assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


