# Test author: Achal Raghav & Vinod G.
# Test suite: MQTT_SAPI
import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116AsyncEventType,
    RS9116PowerSaveModes,
    RS9116MqttQos,
    RS9116CustomFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveProcedureTypes,
    RS9116BLEFeatureBitMap,
    RS9116BLECustomFeatureBitMap
)
from utf.utils.stopwatch import Stopwatch
from retry import retry
import string
from utf.interfaces.wifi import WlanError
import filecmp
import os
import re
import random
from threading import Thread
from typing import Dict
from utf.utils.iperf.iperf_utils import ping
from datetime import datetime
import uuid

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Open MQTT server in the Raspberry pi
        5. Connect to the MQTT server from the DUT
        6. Connect to the MQTT server from the Raspberry pi
        7. Send or receive data on MQTT and verify packet loss tests 
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC Wifi Sniffer 

Note: The test cases added in the file works only in SAPI mode
"""


def ApWirelessOff(switch, wait_time, logger):
    time.sleep(1)
    logger.info(f"Disable the PDU")
    switch.interfaces.pdu_switch.turn_off()
    time.sleep(wait_time)
    logger.info(f"Enable the PDU")
    switch.interfaces.pdu_switch.turn_on()


def ssl_tcp_packet_check(wifi_sniffer, logger, decryption_key: str, dut_mac_address, ap_bssid, print_layers: list,
                     capture_filename, mode=0) -> list:
    current_time = time.time()
    updated_capture_file = 'filter_ssl' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    result_ssl = []
    result_tcp = []
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {ap_bssid})'
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
            if layer_name == "tls":
                logger.info("================= Layer is TLS ===========================")
                filtered_packet = str(packet)
                filtered_packet = filtered_packet.split("Layer ")
                tls_layer_pkt = ""
                ra_address = ""
                ta_address = ""
                logger.info(f"DUT_MAC_ADDRESS: {dut_mac_address},AP_BSSID: {ap_bssid}")
                for layerp in filtered_packet:
                    if ((re.search(".*Receiver address:", layerp) and re.search(".*Transmitter address:", layerp))
                            or (re.search(".*TLS:", layerp))):
                        if re.search(".*TLS:", layerp):
                            tls_layer_pkt = layerp
                        if re.search(".*Receiver address:", layerp) and re.search(".*Transmitter address:", layerp):
                            Received = re.compile(r'Receiver address: (([0-9a-fA-F]:?){12})')
                            receiver_address = re.search(Received, layerp).group()
                            ra_address = (re.search(Received, layerp).group(1)).lower()
                            Transmit = re.compile(r'Transmitter address: (([0-9a-fA-F]:?){12})')
                            Transmitter_address = re.search(Transmit, layerp).group()
                            ta_address = (re.search(Transmit, layerp).group(1)).lower()
                            dut_mac_address_mod = dut_mac_address.lower()
                            ap_bssid_mod = ap_bssid.lower()

                        if ((ra_address == dut_mac_address_mod or ra_address == ap_bssid_mod) and (
                                ta_address == dut_mac_address_mod or ta_address == ap_bssid_mod)) and tls_layer_pkt:
                            logger.info(f"{Transmitter_address}>>>>>>{receiver_address}")
                            logger.info(f"TLS HANDSHAKE PACKET: {tls_layer_pkt}")
                            result_ssl.append(str(tls_layer_pkt))
            if layer_name == "tcp":
                logger.info("=================================== Layer is TCP =================================")
                filtered_packet = str(packet)
                filtered_packet = filtered_packet.split("Layer ")
                tcp_layer_pkt = ""
                logger.info(f"DUT_MAC_ADDRESS: {dut_mac_address},AP_BSSID: {ap_bssid}")
                for layerp in filtered_packet:
                    if re.search(".*TCP:", layerp):
                        tcp_layer_pkt = layerp
                        logger.info(f"TCP PACKET: {tcp_layer_pkt}")
                        result_tcp.append(str(tcp_layer_pkt))

    return result_ssl, result_tcp


def get_mqtt_list(wifi_sniffer, dut_mac_address, logger, decryption_key: str, print_layers: list, capture_filename,
                  mode=0) -> Dict[str, int]:
    mqtt_capture_list = []
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
                    mqtt_layer = str(layer)
                    logger.info(f"As per sniffer capture MQTT packets sent by DUT..{ta_address}  ->  {mqtt_layer}")
                    mqtt_capture_list.append(tuple([mqtt_layer, packet.sniff_timestamp]))
    return mqtt_capture_list


@retry(Exception, delay=15, tries=5)
def join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger):
    ping_count = 10
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
    logger.info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    logger.info(f"DUT MAC_Address: {mac_address}")
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap"
    )
    for count in range(1, 3):
        try:
            join_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            join_fail = 0
            break
        except:
            wifi_dut.interfaces.wifi.initialized = False
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

    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_address)
    logger.info(f"DUT ip : {device_ip}")
    logger.info(f"Initiating ping to DUT ip {device_ip}")
    status = ping(device_ip, 10)
    if status == 1:
        logger.info(f"ping to DUT is successful")
    else:
        logger.info(f"ping to DUT is failed")
    # The below api puts DUT to power save
    logger.info("Enabling WLAN and BT power save")
    enable_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_ps, "WLAN power save failed"
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "BT power save failed"
    return mac_address


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks mqtt connection, subscribe and publish feature when mqtt qos associated is qos1
def test_mqtt_qos1_connect_publish_check_dut_behaviour_TC127757(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    topic = "mytesttopic"
    # The api returns 300 bytes of random data
    message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
    capture_filename = "test_mqtt_qos1_connect_publish_check_dut_behaviour_TC127757"

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    # Both DUT and third-party mqtt client connects to MQTT server
    logger.info("Both DUT and third-party mqtt client connects to MQTT server")
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
        )
    time.sleep(5)
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        logger.info("MQTT Client subscribes to the topic with QOS 1")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)
    # publish a message with the dut
    logger.info("DUT will publish message over the topic")
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=RS9116MqttQos.QOS1)

    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message " \
                                                "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "mqtt client received message with wrong QOS. expected is QOS1"

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    # unsubscribe to the topic
    logger.info("....Unsubscribing to the topic....")
    wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks mqtt connection, subscribe and publish feature when mqtt qos associated is qos0
def test_mqtt_qos0_connect_publish_max_data_1441bytes_check_dut_behaviour_TC127827(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    topic = "mytesttopic"
    # The api returns 1441 bytes of random data
    message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1441))
    capture_filename = "test_mqtt_qos0_connect_publish_max_data_1441bytes_check_dut_behaviour_TC127827"

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    # Both DUT and third-party mqtt client connects to MQTT server
    logger.info("Both DUT and third-party mqtt client connects to MQTT server")
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
        )
    time.sleep(5)
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        logger.info("MQTT client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic)
    # publish a message with the dut
    logger.info("DUT publishes message over the topic")
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode())

    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message " \
                                                "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop the sniffer")
    # unsubscribe to the topic
    logger.info("MQTT client unsubscribes to the topic")
    wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(0, 120)])
def test_mqtt_keep_alive_disable_with_qos1_TC127794(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, keep_alive_time, idle_time
):
    topic = "mytesttopic"
    # The api returns 300 bytes of random data
    message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
    capture_filename = "test_mqtt_keep_alive_disable_with_qos1_TC127794"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

    # Both DUT and third-party mqtt client connects to MQTT server
    logger.info("Both DUT and third-party mqtt client connects to MQTT server")
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt, keepalive_interval=keep_alive_time
    )
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
    time.sleep(5)
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        logger.info("MQTT client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)

    # publish a message with the dut
    logger.info("DUT publishes message over the topic")
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=RS9116MqttQos.QOS1)
    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message " \
                                                "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS0"

    logger.info(f"Wait for {idle_time} seconds")
    time.sleep(idle_time)
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(1)
    timestamp = []
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    mqtt_capture_list = get_mqtt_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["mqtt"], capture_filename)
    if not len(mqtt_capture_list):
        logger.info(f"MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")
        assert 0, "MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the sniffer " \
                  "file "
    for count in mqtt_capture_list:
        if "Ping Request" in count[0]:
            timestamp.append(count[1])
    assert len(timestamp) == 0, f"DUT is sending MQTT-KEEP alive packets even though feature is disabled"
    logger.info("As per sniffer capture no MQTT-KEEP alive packets  sent from DUT")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["disassociated", "wifi_powersave_disable", "bt_powersave_disable", "mqtt_disconnect"])
# The test case checks mqtt publish message with retain option
def test_mqtt_retain_with_qos1_TC127826(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    capture_filename = "test_mqtt_retain_with_qos1_TC127826"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    logger.info("DUT connects to the mqtt server")
    # DUT connects to MQTT server after execution of below api
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt)
    logger.info("MQTT client connects to the mqtt server")
    # mqtt-client connects to MQTT server after execution of below api
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt
    )

    topic = "mytesttopic/1"
    # the below api would generate a message of 300 bytes
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
    # publish a message with the dut with retain 1
    logger.info(f"Publishing message 1 :{message1} with retain bit 1")
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message1.encode(), qos=RS9116MqttQos.QOS1,
                                                 retain=RS9116MqttQos.QOS1)
    logger.info(f"Publishing message 2 :{message2} with retain bit 2")
    # publish a message with the dut with retain 1
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message2.encode(), qos=RS9116MqttQos.QOS1,
                                                 retain=RS9116MqttQos.QOS1)
    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            logger.info("subscribing to the mqtt client")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)
    except:
        time.sleep(1)

    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        #  mqtt client receives messages
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    logger.info("checking for the received message")
    assert len(msgs) == 1, "No message is received by mqtt-client on subscribed topic"
    assert msgs[0].topic == topic, "topic received is not matched"
    assert msgs[0].payload == message2.encode(), "data received on the topic is not matched"
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    # unsubscribe to the topic
    logger.info(f"Unsubscribing to the topic {topic}")
    wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case should produce error 0xFFFFFFD3 as username or password is more than 60 bytes
def test_mqtt_check_error_0xFFFFFFD3_C127802(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger
):
    # The api generates 65 bytes of random data
    username = ''.join(random.choices(string.ascii_uppercase + string.digits, k=65))
    capture_filename = "test_mqtt_check_error_0xFFFFFFD3_C127802"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    logger.info(f"username is {username}")
    with pytest.raises(WlanError) as exc_info:
        # DUT tries to connect to mqtt server
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, username=username)
        logger.info(f"DUT sent {exc_info.value.error_code} code when the username or password is more than 60 bytes")
    assert exc_info.value.error_code == 0xFFFFFFD3, "DUT sent wrong error code, expected is 0xFFFFFFD3"

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks DUT behavior when DUT is trying to connect to MQTT server, but server is not responding
def test_mqtt_invalid_server_TC127801(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger
):
    capture_filename = "test_mqtt_invalid_server_TC127801"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    logger.info(f"MQTT server is not running at 192.168.100.50")
    with pytest.raises(WlanError) as exc_info:
        # After execution of below api DUT connects to MQTT server
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                               mqtt_server="192.168.100.50")
        logger.info(f"DUT sent {exc_info.value.error_code} code when MQTT server is not responding")
    assert exc_info.value.error_code == 0xFF87, "DUT sent wrong error code, expected is 0xFF87"

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks mqtt connection, subscribe and publish feature when mqtt qos associated is qos1
def test_mqtt_server_publish_data_and_check_rejoin_C127758(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes,
        pkt_delay, switch
):
    count_rejoin = set()
    current_time = time.time()
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    capture_filename = "test_mqtt_tx_after_rejoin_testcase24"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    tx_file = "./reports/" + capture_filename + "_tx_file" + file_time_stamp + ".txt"
    with open(tx_file, "w") as temp:
        temp.write(temp_buffer)

    client_devices = [wifi_dut, mqtt_client]

    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
        )

    time.sleep(5)

    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
            logger.info(f"'{mqtt_client.name}' is connected to MQTT server")
    except:
        time.sleep()

    send_count = 0
    ap_power_off = 0
    send_pkts = int((total_bytes / publish_len))

    with open(tx_file, "r") as temp:
        while 1:
            buffer_length = publish_len
            buffer = temp.read(buffer_length)
            if buffer == '':
                break
            else:
                # publish a message with the dut
                if pkt_delay:
                    time.sleep(pkt_delay)
                if ap_power_off:
                    ap_power_off = 0
                    pdu_thread = Thread(target=ApWirelessOff, args=(switch, 10, logger), )
                    pdu_thread.start()
                try:
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                    events = wifi_dut.interfaces.wifi.get_async_events()
                    rejoin_error_events = [event for event in events if
                                           event.event_type == RS9116AsyncEventType.RejoinError]
                    if len(rejoin_error_events):
                        count_rejoin.add(str(rejoin_error_events[0]))
                except:
                    logger.info("Exception Occured")
                    assert False
                finally:
                    if (len(count_rejoin)):
                        logger.info("***** Rejoin Error Occured, publishing data again ****")
                        time.sleep(120)
                        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                count_rejoin.clear()
                send_count = send_count + 1
                if send_count == int((send_pkts / 4)):
                    ap_power_off = 1

    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    rx_file = "./reports/" + capture_filename + "_rx_file" + file_time_stamp + ".txt"
    if len(msgs):
        with open(rx_file, "w") as recv:
            for pkt in msgs:
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists(rx_file):
        logger.info("No MQTT data received at receiver")
        assert 0, "No MQTT data received at receiver"

    result = filecmp.cmp(tx_file, rx_file, shallow=False)
    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 0,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks whether the DUT is able to connect to MQTT server over SSL when authentication feature is enabled
def test_mqtt_server_with_ssl_conn_enable_retain_bit_publish_data_C127759(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    topic = "mytesttopic"
    capture_filename = "test_mqtt_server_with_ssl_conn_enable_retain_bit_publish_data_C127759"
    # The api returns 1441 bytes of random data
    message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=550))
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    # Both DUT and third-party mqtt client connects to MQTT server
    logger.info("Both DUT and third-party mqtt client connects to MQTT server")
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
        )
    time.sleep(5)
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        logger.info("==== MQTT client subscribes to the topic =====")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS0)
    logger.info("=== Clear the previous received messages ===")
    mqtt_client.interfaces.mqtt.received_messages.clear()
    # publish a message with the dut
    logger.info("===== DUT publishes message over the topic ======")
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=RS9116MqttQos.QOS0,
                                                 retain=RS9116MqttQos.QOS1)

    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message " \
                                                "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"
    logger.info("Stop the sniffer")
    # unsubscribe to the topic
    logger.info("====== MQTT client unsubscribes to the topic =======")
    wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info(f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
                f"Handshake Message ==============")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger.info(f"DECRYPTION KEY-->{decryption_key}")
    ssl_pkt, tcp_pkt = ssl_tcp_packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls", "tcp"],
                                        capture_filename, mode=0)
    assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
    assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
    assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
        "Unable to find 'Client Key Exchange' message"
    assert (message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt), \
        "Unable to find 'Encrypted Handshake Message' "
    assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
        "Unable to find 'Change Cipher Spec' message"
    logger.info(f"===== TCP Packet decryprtion and check SYN, FIN, ACK, FIN ACK ======")
    assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
    assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
    assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), \
        "Unable to find ACK"
    assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), \
        "Unable to find FIN ACK "
    logger.info("Disable the wifi and bt power save")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled, 0)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled, 0)
    logger.info(f"=========Disconnect from DUT=======")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 0,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks whether the DUT is able to connect to MQTT server over SSL when authentication feature is enabled
def test_subscribe_mqtt_with_ssl_close_and_subscribe_again_for_5_iter_C127803(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    iter_count = 5
    for i in range(0, iter_count):
        logger.info(f" ====== Running Iteration : {i} ========")
        topic = "mytesttopic"
        # The api returns 1441 bytes of random data
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=400))
        capture_filename = "test_subscribe_mqtt_with_ssl_close_and_subscribe_again_for_5_it_C127803"
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        client_devices = [wifi_dut, mqtt_client]
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        # Both DUT and third-party mqtt client connects to MQTT server
        logger.info("Both DUT and third-party mqtt client connects to MQTT server")
        mqtt_client.interfaces.mqtt.received_messages.clear()
        for device in client_devices:
            device.interfaces.mqtt.mqtt_client_connect_to_server(
                mqtt_server.interfaces.mqtt
            )
        time.sleep(5)
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            logger.info("MQTT client subscribes to the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)

        # publish a message with the dut
        logger.info("DUT publishes message over the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=RS9116MqttQos.QOS1)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message " \
                                                    "received is wrong"
        assert msgs[0].qos == RS9116MqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"
        # unsubscribe to the topic
        logger.info("MQTT client unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
        wifi_dut.interfaces.wifi.mqtt_client_close()
        logger.info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info(f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
                    f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = ssl_tcp_packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid,
                                                ["tls", "tcp"],
                                                capture_filename, mode=0)
        assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
            "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt), \
            "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
            "Unable to find 'Change Cipher Spec' message"
        logger.info(f"===== TCP Packet decryprtion and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), \
            "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), \
            "Unable to find FIN ACK "
        logger.info("Disable the wifi and bt power save")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled, 0)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled, 0)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 0,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks whether the DUT is able to connect to MQTT server over SSL when authentication feature is enabled
def test_qos1_mqtt_with_ssl_publish_diff_length_1_10_100_512_1000_1340_bytes_data_C127789(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    topic = "mytesttopic"
    # The api returns 1441 bytes of random data
    capture_filename = "test_mqtt_with_ssl_publish_diff_length_1_100_512_1000_1340_bytes_data_C127789"
    iter_count = 5
    for i in range(1, iter_count+1):
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        client_devices = [wifi_dut, mqtt_client]
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        # Both DUT and third-party mqtt client connects to MQTT server
        logger.info("Both DUT and third-party mqtt client connects to MQTT server")
        for device in client_devices:
            device.interfaces.mqtt.mqtt_client_connect_to_server(
                mqtt_server.interfaces.mqtt
            )
        time.sleep(5)
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            logger.info("MQTT client subscribes to the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)

        msg_length = [1, 10, 100, 512, 1000, 1340]
        for length in msg_length:
            logger.info(f" Publish data for length : {length} bytes")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            # publish a message with the dut
            logger.info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=RS9116MqttQos.QOS1)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) == 1:
                    break
            assert len(msgs) == 1, "No message is received by mqtt-client"
            assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[
                       0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                       "message " \
                                                       "received is wrong"
            assert msgs[0].qos == RS9116MqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop the sniffer")
        # unsubscribe to the topic
        logger.info("MQTT client unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
        wifi_dut.interfaces.wifi.mqtt_client_close()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop the sniffer")
        logger.info(f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
                    f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = ssl_tcp_packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid,
                                                ["tls", "tcp"],
                                                capture_filename, mode=0)
        assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
            "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt), \
            "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
            "Unable to find 'Change Cipher Spec' message"
        logger.info(f"===== TCP Packet decryprtion and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), \
            "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), \
            "Unable to find FIN ACK "
        logger.info("===== Disconnect from DUT =======")
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 0,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_qos0_mqtt_with_ssl_publish_diff_length_1_10_100_512_1000_1340_bytes_data_C127790(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    topic = "mytesttopic"
    capture_filename = "test_qos0_mqtt_with_ssl_publish_diff_length_1_10_100_512_1000_1340_bytes_data_C127790"
    iter_count = 5
    for i in range(1, iter_count + 1):
        logger.info(f" ==== Running iteration of : {i} ========")
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        client_devices = [wifi_dut, mqtt_client]
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        # Both DUT and third-party mqtt client connects to MQTT server
        logger.info("Both DUT and third-party mqtt client connects to MQTT server")
        for device in client_devices:
            device.interfaces.mqtt.mqtt_client_connect_to_server(
                mqtt_server.interfaces.mqtt
            )
        time.sleep(5)
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            logger.info("MQTT client subscribes to the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS0)

        msg_length = [1, 10, 100, 512, 1000, 1340]
        for length in msg_length:
            logger.info(f" Publish data for length : {length} bytes")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            # publish a message with the dut
            logger.info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=RS9116MqttQos.QOS0)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) == 1:
                    break
            assert len(msgs) == 1, "No message is received by mqtt-client"
            assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[
                       0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                       "message " \
                                                       "received is wrong"
            assert msgs[0].qos == RS9116MqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop the sniffer")
        # unsubscribe to the topic
        logger.info("MQTT client unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
        wifi_dut.interfaces.wifi.mqtt_client_close()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop the sniffer")
        logger.info(f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
                    f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = ssl_tcp_packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid,
                                                ["tls", "tcp"],
                                                capture_filename, mode=0)
        assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
            "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt), \
            "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
            "Unable to find 'Change Cipher Spec' message"
        logger.info(f"===== TCP Packet decryprtion and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), \
            "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), \
            "Unable to find FIN ACK "
        logger.info("===== Disconnect from DUT =======")
        wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 0,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# TCP data validation since ssl supports maximum of 1351 bytes of data transfer
def test_qos0_mqtt_with_tcp_publish_diff_length_1_10_100_512_1000_1390_bytes_data_C127791(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    topic = "mytesttopic"
    capture_filename = "test_qos0_mqtt_with_ssl_publish_diff_length_1_10_100_512_1000_1390_bytes_data_C127791"
    iter_count = 5
    for i in range(1, iter_count + 1):
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        client_devices = [wifi_dut, mqtt_client]
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        # Both DUT and third-party mqtt client connects to MQTT server
        logger.info("Both DUT and third-party mqtt client connects to MQTT server")
        for device in client_devices:
            device.interfaces.mqtt.mqtt_client_connect_to_server(
                mqtt_server.interfaces.mqtt
            )
        time.sleep(5)
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            logger.info("MQTT client subscribes to the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS0)

        msg_length = [1, 10, 100, 512, 1000, 1390]
        for length in msg_length:
            logger.info(f" Publish data for length : {length} bytes")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            # publish a message with the dut
            logger.info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=RS9116MqttQos.QOS0)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) == 1:
                    break
            assert len(msgs) == 1, "No message is received by mqtt-client"
            assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[
                       0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                       "message " \
                                                       "received is wrong"
            assert msgs[0].qos == RS9116MqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop the sniffer")
        # unsubscribe to the topic
        logger.info("MQTT client unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
        wifi_dut.interfaces.wifi.mqtt_client_close()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        mqtt_capture_list = get_mqtt_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["mqtt"],
                                          capture_filename)
        logger.info(f" ===== Mqtt CApture list ========= {mqtt_capture_list}")
        logger.info("===== Disconnect from DUT =======")
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 0,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# TCP data validation since ssl supports maximum of 1351 bytes of data transfer
def test_qos1_mqtt_with_tcp_publish_diff_length_1_10_100_512_1000_1390_bytes_data_C127792(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    topic = "mytesttopic"
    capture_filename = "test_qos1_mqtt_with_ssl_publish_diff_length_1_10_100_512_1000_1390_bytes_data_C127792"
    iter_count = 5
    for i in range(1, iter_count + 1):
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        client_devices = [wifi_dut, mqtt_client]
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        # Both DUT and third-party mqtt client connects to MQTT server
        logger.info("Both DUT and third-party mqtt client connects to MQTT server")
        for device in client_devices:
            device.interfaces.mqtt.mqtt_client_connect_to_server(
                mqtt_server.interfaces.mqtt
            )
        time.sleep(5)
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            logger.info("MQTT client subscribes to the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)

        msg_length = [1, 10, 100, 512, 1000, 1390]
        for length in msg_length:
            logger.info(f" Publish data for length : {length} bytes")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            # publish a message with the dut
            logger.info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=RS9116MqttQos.QOS1)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) == 1:
                    break
            assert len(msgs) == 1, "No message is received by mqtt-client"
            assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[
                       0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                       "message " \
                                                       "received is wrong"
            assert msgs[0].qos == RS9116MqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop the sniffer")
        # unsubscribe to the topic
        logger.info("MQTT client unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
        wifi_dut.interfaces.wifi.mqtt_client_close()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop the sniffer")
        logger.info(f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
                    f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        mqtt_capture_list = get_mqtt_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["mqtt"],
                                          capture_filename)
        logger.info(f" ===== Mqtt CApture list ========= {mqtt_capture_list}")
        logger.info("===== Disconnect from DUT =======")
        wifi_dut.interfaces.wifi.leave()

