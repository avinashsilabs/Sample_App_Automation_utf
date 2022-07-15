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
    DeviceConstants,
    RS9116AsyncEventType,
    RS9116PowerSaveProcedureTypes,
    RS9116CustomFeatureBitMap
    )
from typing import Dict
from utf.interfaces.wifi import WlanError
from datetime import datetime
import uuid
from utf.utils.iperf.iperf_utils import ping


def get_ntp_list(wifi_sniffer, dut_mac_address, decryption_key: str, print_layers: list, capture_filename, mode=0) -> \
        Dict[str, int]:
    ntp_capture_list = []
    source_ip = ""
    destination_ip = ""
    mac_layer = ""
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
            if dut_mac_address in mac_layer:
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


def join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger):
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
    logger.info("Start the sniffer")
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
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SNTPClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            }
        )
    ]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_sntp_unicast_TC19015(
        wifi_sniffer, wifi_dut, wifi_access_point, logger
        ):
    capture_filename = "test_sntp_unicast_TC19015"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
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
    sntp_date_time_response = sntp_date_time.decode().split('.')[0]
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
    ntp_capture_list = get_ntp_list(wifi_sniffer, dut_mac_address, decryption_key, ["ntp"], capture_filename)
    if not len(ntp_capture_list):
        logger.info(f"NTP packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")
    assert len(ntp_capture_list) > 0, f"NTP packets are not captured or one of the 4-way handshake pkts are not " \
                                      f"captured in the sniffer file "

    for ntp_pkt in ntp_capture_list:
        if (ntp_pkt[2] == sntp_server_address) and (ntp_pkt[3] == device_ip):
            logger.info(
                f"As per sniffer SNTP packets received on DUT mac address {dut_mac_address}---->{ntp_pkt[0]}")
            sntp_pkt_sniffer = ntp_pkt[0]
            break

    sntp_pkt_fields = sntp_pkt_sniffer.split("\n")
    for count in sntp_pkt_fields:
        if "Transmit Timestamp:" in count:
            sntp_transmit_time_sniffer = count.split("Transmit Timestamp:")[1].split(".")[0].strip()
    logger.info(f"Date and Time sent by SNTP server as per sniffer capture {sntp_transmit_time_sniffer}")

    logger.info(f"Date and time sent by DUT {sntp_date_time_response}")

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(30, 600)])
def test_sntp_keepalive_TC19016(
        wifi_sniffer, wifi_dut, wifi_access_point, keep_alive_time, idle_time, logger
        ):
    capture_filename = "test_sntp_keepalive_TC19016"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
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
    sntp_date_time_response = sntp_date_time.decode().split('.')[0]

    command_type, ip_version, server_ip = wifi_dut.interfaces.wifi.get_sntp_server_info()
    assert command_type == 6, "Command type received for the body of get_sntp_server_info response is wrong, expected " \
                              "is 6"
    assert ip_version == 4, "Ip version received for the body of get_sntp_server_info response is wrong, expected " \
                            "is 4"
    assert server_ip == sntp_server_address, f"SNTP server ip address received for the body of get_sntp_server_info " \
                                             f"response is wrong, expected " \
                                             "is {sntp_server_address}"
    logger.info(f"wait for {idle_time} sec to check SNTP keep-alive packets in sniffer")
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
    ntp_capture_list = get_ntp_list(wifi_sniffer, dut_mac_address, decryption_key, ["ntp"], capture_filename)
    if not len(ntp_capture_list):
        logger.info(f"NTP packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")
    assert len(ntp_capture_list) > 0, f"NTP packets are not captured or one of the 4-way handshake pkts are not " \
                                      f"captured in the sniffer file "
    for ntp_pkt in ntp_capture_list:
        if (ntp_pkt[2] == sntp_server_address) and (ntp_pkt[3] == device_ip):
            logger.info(
                f"As per sniffer SNTP packets received  on DUT mac address {dut_mac_address}---->{ntp_pkt[0]}")
            sntp_pkt_sniffer = ntp_pkt[0]
            break

    sntp_pkt_fields = sntp_pkt_sniffer.split("\n")
    for count in sntp_pkt_fields:
        if "Transmit Timestamp:" in count:
            sntp_transmit_time_sniffer = count.split("Transmit Timestamp:")[1].split(".")[0].strip()
    logger.info(f"Date and Time sent by SNTP server as per sniffer capture {sntp_transmit_time_sniffer}")

    logger.info(f"Date and time sent by DUT {sntp_date_time_response}")
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
            f"As per sniffer, Number of NTP keep alive packets sent by mac address {dut_mac_address}->{len(timestamp)} while the test has been running for "
            f"{idle_time} sec when keep alive time configured is {keep_alive_time}")

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_sntp_ludp_coexit_TC19017(
        wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger
        ):
    capture_filename = "test_sntp_ludp_coexit_TC19017"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
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

    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.wlan_get_status()
    assert exc_info.value.error_code == 0xBB23, f"DUT sent wrong error code. expected is {0xBB23}"
    logger.info(f"DUT sent error code-> {exc_info.value.error_code} when trying to open SNTP client, but already a "
                f"socket is opened "
                f"at port number 123")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()
