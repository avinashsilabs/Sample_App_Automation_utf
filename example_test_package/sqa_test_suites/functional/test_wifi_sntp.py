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
    SocketType,
    Cipher,
    DeviceConstants,
    RS9116AsyncEventType,
    )
from typing import Dict
from interfaces.wifi import WlanError


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


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.SNTPClient | RS9116TCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_sntp_unicast_TC19015(
        wifi_sniffer, wifi_dut, wifi_access_point, logger
        ):
    capture_filename = "test_sntp_unicast_TC19015"
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
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    sntp_server_address = wifi_dut.interfaces.wifi.get_sntp_server_ip()
    wifi_dut.interfaces.wifi.sntp_create(server_ip=sntp_server_address)
    logger.info("wait for 10 seconds to receive SNTP asynchronous messages")
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
    logger.info("wait for 5 seconds to receive SNTP asynchronous messages")
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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.SNTPClient | RS9116TCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(60, 600)])
def test_sntp_keepalive_TC19016(
        wifi_sniffer, wifi_dut, wifi_access_point, keep_alive_time, idle_time, logger
        ):
    capture_filename = "test_sntp_keepalive_TC19016"
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
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    sntp_server_address = wifi_dut.interfaces.wifi.get_sntp_server_ip()
    wifi_dut.interfaces.wifi.sntp_create(server_ip=sntp_server_address)
    logger.info("wait for 10 seconds to receive SNTP asynchronous messages")
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
    logger.info(f"wait for {idle_time} to check SNTP keep-alive packets in sniffer")
    time.sleep(idle_time)
    wifi_dut.interfaces.wifi.sntp_delete()
    logger.info("wait for 5 seconds to receive SNTP asynchronous messages")
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
            logger.info(f"SNTP response body received in the sniffer {ntp_pkt}\n")
    timestamp = []
    for ntp_pkt in ntp_capture_list:
        if ntp_pkt[2] == device_ip:
            timestamp.append(ntp_pkt[1])

    if len(timestamp):
        for count in range(0, len(timestamp) - 1):
            time_diff = float(timestamp[count + 1]) - float(timestamp[count])
            if time_diff > (4 + keep_alive_time):
                logger.info(f"NTP keep alive packets are not sending every {keep_alive_time}sec on {count + 1} time")
        logger.info(
            f"Number of NTP keep alive packets sent->{len(timestamp)} while the test has been running for "
            f"{idle_time} sec when keep alive time configured is {keep_alive_time}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.SNTPClient | RS9116TCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_sntp_ludp_coexit_TC19017(
        wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger
        ):
    capture_filename = "test_sntp_ludp_coexit_TC19017"
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
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    # Open UDP socket remotely
    remote_socket.interfaces.socket.start_server(socket_type=1)
    # Open UDP socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
    assert sock == 0, "socket id received is not matched. Expected is 0"
    # DUT binds to socket(device_ip, 5001)
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 123)
    # DUT sends data over udp socket
    wifi_dut.interfaces.wifi.send_to(sock, 50, remote_socket.interfaces.socket.server_ip,
                                     remote_socket.interfaces.socket.server_port)

    sntp_server_address = wifi_dut.interfaces.wifi.get_sntp_server_ip()
    wifi_dut.interfaces.wifi.sntp_create(server_ip=sntp_server_address)
    logger.info("wait for 10 seconds to receive SNTP asynchronous messages")

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
    assert sntp_status == 2, "SNTP connection is successful even though the UDP socket at 123 port is already opened " \
                             "in the DUT which is not expected "

    status = wifi_dut.interfaces.wifi.wlan_get_status()
    status_code = "NULL"
    status = status.split(b"\n")
    for line in status:
        if b"status:" in line:
            status_code = line.split(b":")[1].decode().strip("\r").strip()
    logger.info(f"DUT sent error code-> {status_code} when trying to open SNTP client, but already a socket is opened "
                f"at port number 123")
    assert status_code == "0xBB23", "Observed wrong error code, expected is 0xBB23"
