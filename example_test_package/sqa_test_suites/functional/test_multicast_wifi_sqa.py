# Test author: Vinod.G
# Test suite: Multicast test suite
import time
import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, DeviceConstants, SocketParams, \
    MulticastParams, RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes
from utf.utils.iperf.iperf_utils import ping
from datetime import datetime
import uuid
from typing import Dict

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


def get_igmp_list(wifi_sniffer, dut_mac_address, logger, decryption_key: str, print_layers: list, capture_filename,
                  mode=0) -> Dict[str, int]:
    igmp_capture_list = []
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {dut_mac_address})'
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
            if layer_name == "wlan":
                mac_layer = str(layer)
                for count in mac_layer.split("\n"):
                    if "Transmitter address" in count:
                        ta_address = count.split(": ")[1].strip()
            if layer_name in print_layers:
                if ta_address == dut_mac_address:
                    igmp_layer = str(layer)
                    logger.info(f"As per sniffer capture IGMP packets sent by DUT..{ta_address}  ->  {igmp_layer}")
                    igmp_capture_list.append(tuple([igmp_layer, packet.sniff_timestamp]))
    return igmp_capture_list


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
            ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
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
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)
    return mac_address


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
        }
    )
]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
                             "disassociated"])
def test_wifi_multicast_receive_TC19369(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client, logger):
    capture_filename = "test_wifi_multicast_receive_TC19369"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
    logger.info(f"DUT joining to the multicast group {multicast_ip}")
    wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
    socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
    assert socket_id == 0, f"socket id received is wrong, expected is 0"
    logger.info(f"socket id received is {socket_id} which is expected")
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

    logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
    multicast_client.interfaces.multicast.start_server()

    logger.info(
        f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
    multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
    multicast_client.interfaces.multicast.socket_close()
    time.sleep(30)
    result = wifi_dut.interfaces.wifi.close_socket(socket_id)
    assert b"success" in result, "unable to close opened socket in the dut"
    logger.info("Successfully closed opened socket in the DUT")
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)
    bytes_received = int(result.split(b":")[1])
    bytes_sent = (no_of_pkts * buffer_length)
    packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)
    logger.info(f"Packet loss {packet_loss}")
    assert packet_loss < 20, "Packet loss is not in tolerance level"
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    wifi_dut.interfaces.wifi.leave_multicast_group(multicast_ip=multicast_ip)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    igmp_list = get_igmp_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["igmp"], capture_filename)
    assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
                             "disassociated"])
def test_wifi_multicast_group_leave_TC19370(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client, logger):
    capture_filename = "test_wifi_multicast_group_leave_TC19370"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

    for count in range(0, 3):
        if count % 2 == 0:
            logger.info(f"DUT joining to the multicast group {multicast_ip}")
            wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
        else:
            wifi_dut.interfaces.wifi.leave_multicast_group(ip_version, multicast_ip)
        socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
        assert socket_id == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"socket id received is {socket_id} which is expected")
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)
        logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
        multicast_client.interfaces.multicast.start_server()

        logger.info(
            f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
        multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
        multicast_client.interfaces.multicast.socket_close()
        time.sleep(30)
        result = wifi_dut.interfaces.wifi.close_socket(socket_id)
        assert b"success" in result, "unable to close opened socket in the dut"
        logger.info("Successfully closed opened socket in the DUT")
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
            logger.info("No data is received by DUT on multicast socket when the device is left from multicast group "
                        "which is expected")

    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    get_igmp_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["igmp"], capture_filename)
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
                             "disassociated"])
def test_wifi_multicast_filter_select_all_TC19372(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client, logger):
    capture_filename = "test_wifi_multicast_filter_select_all_TC19372"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

    wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_SET_ALL, multicast_mac)
    logger.info(f"DUT joining to the multicast group {multicast_ip}")
    wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
    socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
    assert socket_id == 0, f"socket id received is wrong, expected is 0"
    logger.info(f"socket id received is {socket_id} which is expected")
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

    logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
    multicast_client.interfaces.multicast.start_server()

    logger.info(
        f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
    multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
    multicast_client.interfaces.multicast.socket_close()
    time.sleep(30)
    result = wifi_dut.interfaces.wifi.close_socket(socket_id)
    assert b"success" in result, "unable to close opened socket in the dut"
    logger.info("Successfully closed opened socket in the DUT")
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)

    bytes_received = int(result.split(b":")[1])
    bytes_sent = (no_of_pkts * buffer_length)
    packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)
    logger.info(f"Packet loss {packet_loss}")
    assert packet_loss < 20, "Packet loss is not in tolerance level"
    wifi_dut.interfaces.wifi.leave_multicast_group(multicast_ip=multicast_ip)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    get_igmp_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["igmp"], capture_filename)
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
                             "disassociated"])
def test_wifi_multicast_filter_clear_all_TC19373(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client, logger):
    capture_filename = "test_wifi_multicast_filter_clear_all_TC19373"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

    wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_CLEAR_AL, multicast_mac)

    logger.info(f"DUT joining to the multicast group {multicast_ip}")
    wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
    socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
    assert socket_id == 0, f"socket id received is wrong, expected is 0"
    logger.info(f"socket id received is {socket_id} which is expected")
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

    logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
    multicast_client.interfaces.multicast.start_server()
    logger.info(
        f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
    multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
    multicast_client.interfaces.multicast.socket_close()
    time.sleep(30)
    result = wifi_dut.interfaces.wifi.close_socket(socket_id)
    assert b"success" in result, "unable to close opened socket in the dut"
    logger.info("Successfully closed opened socket in the DUT")
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)

    bytes_received = int(result.split(b":")[1])
    assert bytes_received == 0, "Data received on multicast socket even though multicast_filter_clear_all is selected "
    logger.info("Data is not received on multicast socket when multicast_filter_clear_all filter is selected which is "
                "expected")
    wifi_dut.interfaces.wifi.leave_multicast_group(multicast_ip=multicast_ip)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    get_igmp_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["igmp"], capture_filename)
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
                             "disassociated"])
def test_wifi_multicast_filter_clear_specific_TC19374(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client,
                                                      logger):
    capture_filename = "test_wifi_multicast_filter_clear_specific_TC19374"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

    for count in range(0, 2):
        if count == 1:
            wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_CLEAR_BIT, multicast_mac)
        logger.info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
        socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
        assert socket_id == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"socket id received is {socket_id} which is expected")
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

        logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
        multicast_client.interfaces.multicast.start_server()

        logger.info(
            f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
        multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
        multicast_client.interfaces.multicast.socket_close()
        time.sleep(30)
        result = wifi_dut.interfaces.wifi.close_socket(socket_id)
        assert b"success" in result, "unable to close opened socket in the dut"
        logger.info("Successfully closed opened socket in the DUT")
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
    wifi_dut.interfaces.wifi.leave_multicast_group(multicast_ip=multicast_ip)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    get_igmp_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["igmp"], capture_filename)
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
                             "disassociated"])
def test_wifi_multicast_filter_add_specific_TC19375(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client,
                                                    logger):
    capture_filename = "test_wifi_multicast_filter_add_specific_TC19375"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

    for count in range(0, 2):
        if count == 0:
            wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_CLEAR_AL, multicast_mac)
        else:
            wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_ADD_BIT, multicast_mac)
        logger.info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
        socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
        assert socket_id == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"socket id received is {socket_id} which is expected")
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

        logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
        multicast_client.interfaces.multicast.start_server()

        logger.info(
            f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
        multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
        multicast_client.interfaces.multicast.socket_close()
        time.sleep(30)
        result = wifi_dut.interfaces.wifi.close_socket(socket_id)
        assert b"success" in result, "unable to close opened  socket in the dut"
        logger.info("Successfully closed opened socket in the DUT")
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

    wifi_dut.interfaces.wifi.leave_multicast_group(multicast_ip=multicast_ip)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    get_igmp_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["igmp"], capture_filename)
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
