import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xPowerSaveModes, \
    RS9116AsyncEventType, Si91xCustomFeatureBitMap
from typing import Dict
from utf.interfaces.wifi import WlanError
from datetime import datetime
import uuid
from utf.utils.iperf.iperf_utils import ping

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
            "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SNTPClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            }
        )
    ]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_sntp_unicast_TC19015(
        wifi_sniffer, wifi_dut, wifi_access_point, logger, sl_collections):
    capture_filename = "test_sntp_unicast_TC19015"
    result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=20,
                                                             retry_count=3, rejoin_parms=[0, 6, 40, 0])
    device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
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
    assert sntp_status == 1, "SNTP status received for SNTP connection request is incorrect expected is 1"

    command_type, sntp_time = wifi_dut.interfaces.wifi.get_sntp_time()
    assert command_type == 2, "get_sntp_time response is incorrect, expected is 2"
    command_type, sntp_date_time = wifi_dut.interfaces.wifi.get_sntp_timedate()
    sntp_date_time_response = sntp_date_time.decode().split('.')[0]
    assert command_type == 3, "get_sntp_timedate response is incorrect, expected is 3"
    command_type, ip_version, server_ip = wifi_dut.interfaces.wifi.get_sntp_server_info()
    assert command_type == 6, "get_sntp_server_info response is incorrect, expected is 6"
    assert ip_version == 4, "get_sntp_server_info response is incorrect, expected ip_version is 4"
    assert server_ip == sntp_server_address, f"get_sntp_server_info response is incorrect, expected is {sntp_server_address}"

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
    assert sntp_status == 1, "SNTP message for SNTP delete request is wrong expected is 1 "
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger.info(f"DECRYPTION KEY-->{decryption_key}")

    ntp_capture_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["ntp"],
                                                  capture_filename, ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    if not len(ntp_capture_list):
        logger.info(f"NTP packets or one of the 4-way handshake pkts are not captured")
    assert len(ntp_capture_list) > 0, f"NTP packets or one of the 4-way handshake pkts are not captured"

    for ntp_pkt in ntp_capture_list:
        if (ntp_pkt[2] == sntp_server_address) and (ntp_pkt[3] == device_ip):
            logger.info(
                f"As per sniffer SNTP packets received on DUT mac address {dut_mac_address}---->{ntp_pkt[0]}")
            sntp_pkt_sniffer = ntp_pkt[0]
            break
    if sntp_pkt_sniffer:
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
        wifi_sniffer, wifi_dut, wifi_access_point, keep_alive_time, idle_time, logger, sl_collections
        ):
    capture_filename = "test_sntp_keepalive_TC19016"
    result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=20,
                                                             retry_count=3, rejoin_parms=[0, 6, 40, 0])
    device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    sntp_server_address = wifi_dut.interfaces.wifi.get_sntp_server_ip()
    wifi_dut.interfaces.wifi.sntp_create(server_ip=sntp_server_address)
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
    assert sntp_status == 1, "SNTP status received for SNTP connection request is incorrect expected is 1"
    command_type, sntp_time = wifi_dut.interfaces.wifi.get_sntp_time()
    assert command_type == 2, "get_sntp_time response is incorrect, expected is 2"
    command_type, sntp_date_time = wifi_dut.interfaces.wifi.get_sntp_timedate()
    assert command_type == 3, "get_sntp_timedate response is incorrect, expected is 3"
    sntp_date_time_response = sntp_date_time.decode().split('.')[0]

    command_type, ip_version, server_ip = wifi_dut.interfaces.wifi.get_sntp_server_info()
    assert command_type == 6, "get_sntp_server_info response is incorrect, expected is 6"
    assert ip_version == 4, "get_sntp_server_info response is incorrect, expected ip_version is 4"

    assert server_ip == sntp_server_address, f"get_sntp_server_info response is incorrect, expected is {sntp_server_address}"
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
    assert sntp_status == 1, "SNTP message for SNTP delete request is incorrect expected is 1"
    wifi_sniffer.interfaces.capture.stop_capture()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger.info(f"DECRYPTION KEY-->{decryption_key}")

    ntp_capture_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["ntp"],
                                                            capture_filename, ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    if not len(ntp_capture_list):
        logger.info(f"NTP packets are not captured or one of the 4-way handshake pkts are not captured in the")
    assert len(ntp_capture_list) > 0, f"NTP packets are not captured or one of the 4-way handshake pkts"

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
        wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger, sl_collections):
    capture_filename = "test_sntp_ludp_coexit_TC19017"
    result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=20,
                                                             retry_count=3, rejoin_parms=[0, 6, 40, 0])
    device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

    # Open UDP socket remotely
    remote_socket.interfaces.socket.start_server(socket_type=1)
    # Open UDP socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
    assert sock == 0, "socket id received is not matched. Expected is 0"
    # DUT binds to socket(device_ip, 5001)
    wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=123,
                                  timeout=15)
    wifi_dut.interfaces.wifi.bsdSocketSendTo(socket_fd=sock, data="ABCDEFGHIJKL", ip_addr=remote_socket.interfaces.socket.server_ip,
                                             port=remote_socket.interfaces.socket.server_port)

    sntp_server_address = wifi_dut.interfaces.wifi.get_sntp_server_ip()
    wifi_dut.interfaces.wifi.sntp_create(server_ip=sntp_server_address)

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
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()
