# Test author: Vinod.G
# Test suite: MQTT_INTERNAL
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
    RS9116BLECustomFeatureBitMap,
    RS9116StoreConfiguration
)
from utf.utils.stopwatch import Stopwatch
import string
from utf.interfaces.wifi import WlanError
import filecmp
import os
import random
from utf import UtfDatabaseProperties
from threading import Thread
from utf.utils import mac_address_to_string
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

Note: The test cases added in the file works only in AT mode
"""


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


def join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger):
    ping_count = 10
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
    logger.info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )

    mac_address = mac_address_to_string(wifi_dut.interfaces.wifi.mac_address)

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
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
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
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid | RS9116BLEFeatureBitMap.RS9113_RS9116_Compatible_Feature,
            "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
            "rejoin_max_retry": 10,
            "scan_interval": 6,
            "beacon_missed_count": 40,
            "first_time_retry": 0,
            "set_send_feature_frame": True,
        }
    )
]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks mqtt connection, subscribe and publish feature when mqtt qos associated is qos0
def test_mqtt_qos0_connect_sub_publish_TC19241_TC19243_TC19252(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    # The api returns 100 bytes of random data
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    # The api returns 200 bytes of random data
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))

    capture_filename = "test_mqtt_qos0_connect_sub_publish_TC19252"

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)

    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    # Both DUT and third-party mqtt client connects to MQTT server
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
        )
    time.sleep(5)
    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic1)
    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic2)
    except:
        time.sleep(1)

    # publish a message with the third-party mqtt client
    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, message1.encode())
    time.sleep(1)
    # publish a message with the dut
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic2, message2.encode())

    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by DUT"
    assert msgs[0].topic == topic1, "No message received by DUT on subscribed topic"
    assert msgs[0].payload.decode() == message1, "No message is received by DUT on subscribed topic or message " \
                                                 "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS0, "DUT received message with wrong QOS. expected is QOS0"
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break

    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic2, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].qos == RS9116MqttQos.QOS0, "DUT sent message with wrong QOS. expected is QOS0"
    assert msgs[0].payload.decode() == message2, "No message is received by mqtt-client on subscribed topic or " \
                                                 "message " \
                                                 "received is wrong"

    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 1
    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 0
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks mqtt connection, subscribe and publish feature when mqtt qos associated is qos1
def test_mqtt_qos1_connect_sub_publish_TC19254(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    # The api returns 100 bytes of random data
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    # The api returns 200 bytes of random data
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))

    capture_filename = "test_mqtt_qos1_connect_sub_publish_TC19254"

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    # Both DUT and third-party mqtt client connects to MQTT server
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
        )
    time.sleep(5)
    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic1, qos=RS9116MqttQos.QOS1)
    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic2, qos=RS9116MqttQos.QOS1)
    except:
        time.sleep(1)

    # publish a message with the third-party mqtt client
    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, message1.encode(), qos=RS9116MqttQos.QOS1)
    time.sleep(1)
    # publish a message with the dut
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic2, message2.encode(), qos=RS9116MqttQos.QOS1)

    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by DUT"
    assert msgs[0].topic == topic1, "No message received by DUT on subscribed topic"
    assert msgs[0].payload.decode() == message1, "No message is received by DUT on subscribed topic or message " \
                                                 "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "DUT received message with wrong QOS. expected is QOS1"
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break

    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic2, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
    assert msgs[0].payload.decode() == message2, "No message is received by mqtt-client on subscribed topic or " \
                                                 "message " \
                                                 "received is wrong"

    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 1
    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 0
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks DUT behavior when DUT is trying to connect to MQTT server, but server is not responding
def test_mqtt_invalid_server_TC19242(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger
):
    capture_filename = "test_mqtt_invalid_server_TC19242"
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


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks DUT behavior when DUT is tyring to connect to MQTT server with client id, but the same client
# id is already being used by another mqtt client
def test_mqtt_common_clientid_TC19245(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    capture_filename = "test_mqtt_common_clientid_TC19245"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    mqtt_client_id = "mqtt_908765436789876589"
    topic = "mytesttopic/#"
    # DUT connects to MQTT server
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, client_id=mqtt_client_id)
    # mqtt-client connects to MQTT server
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, client_id=mqtt_client_id)
    time.sleep(5)
    mqtt_remote_terminate = False
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.MQTT_REMOTE_TERMINATE:
                mqtt_remote_terminate = True
                break
    assert mqtt_remote_terminate, "AT+RSI_MQTT_REMOTE_TERMINATE not found in async results"
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(1)
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    mqtt_capture_list = get_mqtt_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["mqtt"], capture_filename)
    if not len(mqtt_capture_list):
        logger.info(f"MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")

        assert 0, (f"MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the "
                   f"sniffer file")

    for count in mqtt_capture_list:
        if "Connect Command" in count[0]:
            flag = True
            mqtt_fields = count[0].split("\n")

            for field in mqtt_fields:
                if "Client ID:" in field:
                    client_id_capture = field.split(":")[1].strip()
                    logger.info(f"MQTT client id captured in the sniffer {client_id_capture}")
                    break
    if not flag:
        logger.info(f"MQTT-CONNECT packet is not captured")
        assert 0, f"MQTT-CONNECT packet is not captured"
    wifi_dut.interfaces.mqtt._mqtt_client_connected = False

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.mqtt_server("raspi_mosquitto_auth")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks mqtt connection, subscribe and publish feature when password based authentication feature is
# enabled on mqtt server
def test_mqtt_authentication_TC19246(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    # The api returns 100 bytes of random data
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    # The api returns 200 bytes of random data
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))

    capture_filename = "test_mqtt_authentication_TC19246"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    # Both DUT and third-party mqtt client connects to MQTT server
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
        )
    time.sleep(5)
    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic1, qos=RS9116MqttQos.QOS1)
    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic2, qos=RS9116MqttQos.QOS1)
    except:
        time.sleep(1)

    # publish a message with the third-party mqtt client
    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, message1.encode(), qos=RS9116MqttQos.QOS1)
    time.sleep(1)
    # publish a message with the dut
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic2, message2.encode(), qos=RS9116MqttQos.QOS1)

    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by DUT"
    assert msgs[0].topic == topic1, "No message received by DUT on subscribed topic"
    assert msgs[0].payload.decode() == message1, "No message is received by DUT on subscribed topic or message " \
                                                 "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "DUT received message with wrong QOS. expected is QOS1"
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break

    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic2, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
    assert msgs[0].payload.decode() == message2, "No message is received by mqtt-client on subscribed topic or " \
                                                 "message " \
                                                 "received is wrong"

    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 1
    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 0

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.mqtt_server("raspi_mosquitto_auth")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks DUT behavior when trying to connect to MQTT server with wrong credentials
def test_mqtt_authentication_wrong_cred_TC19247(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger
):
    capture_filename = "test_mqtt_authentication_wrong_cred_TC19247"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    with pytest.raises(RuntimeError) as exc_info:
        # After execution of below api DUT connects to MQTT server
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                               username="wrong_user",
                                                               password="wrong_password")
    logger.info(f"DUT received error {exc_info.value}")
    logger.info(f"MQTT connection failed when trying to connect with wrong credentials which is expected behavior")
    assert str(exc_info.value) == "MQTT Connection error 0x5: The Client is not authorized to connect", "DUT sent " \
                                                                                                        "wrong " \
                                                                                                        "error code, " \
                                                                                                        "expected is " \
                                                                                                        "0x0005 "
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "wifi_powersave_disable", "mqtt_disconnect"])
# The test case checks mqtt publish message with retain option
def test_mqtt_retain_TC19256(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    capture_filename = "test_mqtt_retain_TC19256"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    # DUT connects to MQTT server after execution of below api
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt)
    # mqtt-client connects to MQTT server after execution of below api
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt
    )

    topic = "mytesttopic/1"
    message1 = "12345"
    message2 = "retain_test"
    # publish a message with the dut with retain 1
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message1.encode(), qos=RS9116MqttQos.QOS1,
                                                 retain=RS9116MqttQos.QOS1)
    # publish a message with the dut with retain 1
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message2.encode(), qos=RS9116MqttQos.QOS1,
                                                 retain=RS9116MqttQos.QOS1)
    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)
    except:
        time.sleep(1)

    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        #  mqtt client receives messages
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by mqtt-client on subscribed topic"
    assert msgs[0].topic == topic, "topic received is not matched"
    assert msgs[0].payload == message2.encode(), "data received on the topic is not matched"
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks mqtt publish message with retain option
def test_mqtt_delete_retain_message_TC19262(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    capture_filename = "test_mqtt_delete_retain_message_TC19262"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    # DUT connects to MQTT server after execution of below api
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt)
    # mqtt-client connects to MQTT server after execution of below api
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt
    )

    topic = "mytesttopic/1"
    message1 = "12345"
    # publish a message with the dut with retain 1
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message1.encode(), qos=RS9116MqttQos.QOS1,
                                                 retain=RS9116MqttQos.QOS1)
    # publish a message with the dut with retain 1
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, "", qos=RS9116MqttQos.QOS1,
                                                 retain=RS9116MqttQos.QOS1)
    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)
    except:
        time.sleep(1)

    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        #  mqtt client receives messages
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 0, "paho-mqtt-client received a message even though the retained message is deleted in the " \
                           "server "
    logger.info("paho-mqtt-client doesn't receive a message on subscribed topic as the retained message is deleted at "
                "the server which is expected behavior")

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# the test case checks MQTT unsubscribe functionality
def test_mqtt_unsubscribe_TC19260(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    capture_filename = "test_mqtt_unsubscribe_TC19260"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    # DUT connects to MQTT server after execution of below api
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt)
    # mqtt-client connects to MQTT server after execution of below api
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt
    )

    topic = "mytesttopic/1"
    message = "unsubscribe_test"
    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        # DUT subscribes the selected topic
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic)

    asynchronous_request_time = 0
    for count in range(0, 2):
        if count == 1:
            #  DUT unsubscribes the selected topic
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
        # DUT publishes messages on selected topic
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode())

        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            if count == 0:
                # DUT receives message on subscribed topic  after execution of below api
                msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()

            else:
                # DUT receives message on subscribed topic  after execution of below api
                msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages(since_time=asynchronous_request_time)

            # The api returns asynchronous messages received by dut
            events = wifi_dut.interfaces.wifi.get_async_events()
            time.sleep(2)
            if len(events):
                for event in events:
                    asynchronous_request_time = event.timestamp + 1

        if count == 0:
            assert len(msgs) == 1, "No message received by DUT on subscribed topic"
            assert msgs[0].topic == topic
            assert msgs[0].payload == message.encode()
        else:
            assert len(msgs) == 0, "DUT received message on unsubscribed topic which is not expected"
        logger.info("DUT doesn't receive message after topic is unsubscribed in DUT when the data is sent from the "
                    "third-party "
                    "mqtt client which is expected behavior")
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# the test case runs mqtt sequence multiple times
def test_mqtt_sequence_TC19277(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    capture_filename = "test_mqtt_sequence_TC19277"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    message = "unsubscribe_test"
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    for count in range(0, 20):
        # DUT connects to MQTT server after execution of below api
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)

        if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
            # DUT subscribes the selected topic
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic1)
        # DUT publishes the message on selected topic
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic2, message.encode())
        # mqtt-disconnect
        wifi_dut.interfaces.mqtt.mqtt_client_close()
        mqtt_server.interfaces.mqtt.stop_server()
        time.sleep(1)
        mqtt_server.interfaces.mqtt.start_server()

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks mqtt functionality after DUT is connected to AP second time
def test_mqtt_reconnect_testcase_23(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    capture_filename = "test_mqtt_reconnect_testcase_23"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    for count in range(0, 20):
        # DUT connects to MQTT server after execution of below api
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)

        if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
            # DUT subscribes the selected topic
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe("mytesttopic/1")
        # DUT publishes the message on selected topic
        wifi_dut.interfaces.mqtt.mqtt_client_publish("mytesttopic/2", "unsubscribe_test".encode())
        # Disconnect to the Access point
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.mqtt._mqtt_client_connected = False
        # Wireless initialization. This is mandatory step after disconnection
        wifi_dut.interfaces.wifi.wireless_init()
        for count_iteration in range(1, 3):
            try:
                join_fail = 1
                # DUT connects to AP after join_ap API is executed
                logger.info("Joining to the Wifi Access Point")
                wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
                join_fail = 0
                break
            except:
                wifi_dut.interfaces.wifi.initialized = False
                logger.info(
                    f"Joining to the Wifi Access point is failed. retry count -> {count} in test iteration {count_iteration}")
                time.sleep(1)
        if join_fail:
            logger.info(f"Joining to the AP has failed")
            assert join_fail == 0, "Joining to the AP is failed"
        for count_iteration in range(1, 3):
            ip_fail = 1
            try:
                # DUT gets ipaddress through DHCP process after start_ip API is executed
                logger.info("DUT gets ipaddress through DHCP ")
                ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
                ip_fail = 0
                break
            except:
                logger.info(
                    f"Get IP address through dhcp process is failed. retry count -> {count} in iteration {count_iteration}")
                time.sleep(1)
        if ip_fail:
            logger.info(f"DUT unable to get IP address")
            assert ip_fail == 0, "ip setting in DUT has failed"
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# DUT functionality when trying to connect to MQTT server with client-id NULL
def test_mqtt_common_clientid_null_TC19269(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
):
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    # The api returns 100 bytes of random data
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    # The api returns 200 bytes of random data
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
    capture_filename = "test_mqtt_common_clientid_null_TC19269"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    # Both DUT and third-party mqtt client connects to MQTT server
    for device in client_devices:
        if device == wifi_dut:
            device.interfaces.mqtt.mqtt_client_connect_to_server(
                mqtt_server.interfaces.mqtt, client_id=""
            )
        else:
            device.interfaces.mqtt.mqtt_client_connect_to_server(
                mqtt_server.interfaces.mqtt
            )

    time.sleep(2)
    # Both DUT and third-party mqtt client subscribe on topic mytesttopic/#
    for device in client_devices:
        sw = Stopwatch()
        while sw.elapsed_sec < 5:
            time.sleep(0.1)
            if device.interfaces.mqtt.mqtt_client_is_connected:
                device.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
                logger.info(f"'{device.name}' is connected to MQTT server")
                break
        else:
            assert (
                device.interfaces.mqtt.mqtt_client_is_connected
            ), f"Client '{device.name}' did not connect to MQTT server"

    # publish a message with the dut
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, message1.encode(), qos=RS9116MqttQos.QOS1)
    time.sleep(2)
    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic2, message2.encode(), qos=RS9116MqttQos.QOS1)

    for device in client_devices:
        # allow some time for both clients to receive all messages
        sw = Stopwatch()
        msgs = []
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            # Both DUT and mqtt client receive messages
            msgs = device.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 2:
                break

        assert len(msgs) == 2, "No message is received by DUT and mqtt-client"
        assert msgs[0].topic == topic1, "No message received by DUT on subscribed topic"
        assert msgs[0].payload.decode() == message1, "No message is received by DUT on subscribed topic or message " \
                                                     "received is wrong"
        assert msgs[0].qos == RS9116MqttQos.QOS1, "DUT received message with wrong QOS. expected is QOS0"
        assert msgs[1].topic == topic2, "No message received by mqtt-client on subscribed topic"
        assert msgs[1].qos == RS9116MqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS0"
        assert msgs[1].payload.decode() == message2, "No message is received by mqtt-client on subscribed topic or " \
                                                     "message " \
                                                     "received is wrong"

    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 2
    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 0

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


def ApWirelessOff(switch, wait_time, logger):
    time.sleep(1)
    logger.info(f"Disable the PDU")
    switch.interfaces.pdu_switch.turn_off()
    time.sleep(wait_time)
    logger.info(f"Enable the PDU")
    switch.interfaces.pdu_switch.turn_on()


@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_tx_after_rejoin_testcaseC19273(
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


@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_init_after_rejoin_fail_TC19265(wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut,
                                             logger, publish_len, total_bytes, pkt_delay, switch):
    current_time = time.time()
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    capture_filename = "test_mqtt_init_after_rejoin_fail_TC19265"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    tx_file = "./reports/" + capture_filename + "_tx_file" + file_time_stamp + ".txt"
    with open(tx_file, "w") as temp:
        temp.write(temp_buffer)

    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt
    )

    time.sleep(1)

    logger.info("** Disable the PDU **")
    switch.interfaces.pdu_switch.turn_off()
    time.sleep(120)
    logger.info("Rejoining to the AP has failed as AP is in down state")
    logger.info("** Enable the PDU **")
    switch.interfaces.pdu_switch.turn_on(delay=60)
    wifi_dut.interfaces.wifi.initialized = False
    wifi_dut.interfaces.wifi.associated = False
    time.sleep(2)
    logger.info("Joining to the AP again")
    for count in range(1, 4):
        try:
            join_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            join_fail = 0
            break
        except Exception as err:
            wifi_dut.interfaces.wifi.initialized = False
            logger.info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
            time.sleep(10)
            if "Error code: 0x2" in str(err):
                logger.info("Device already in connected state need to disconnect before connect")
                logger.info("Initiating disconnect for cleanup")
                wifi_dut.interfaces.wifi.leave(skip_check_for_association=True)
                time.sleep(5)
                logger.info("cfg disable")
                # Disables the store configuration
                wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
                if count == 2:
                    raise
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
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)

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
        time.sleep(1)

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

                try:
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                except:
                    time.sleep(2)
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)

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


@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(100, 102400, 0.5)])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_rx_after_rejoin_TC19270(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
):
    current_time = time.time()
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    capture_filename = "test_mqtt_rx_after_rejoin_TC19270"
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

    time.sleep(1)

    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
        logger.info(f"'{wifi_dut.name}' is connected to MQTT server")

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
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                except:
                    time.sleep(120)
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                send_count = send_count + 1
                if send_count == int((send_pkts / 4)):
                    ap_power_off = 1

    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
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


@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_publish_qos1_TC19272(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
):
    current_time = time.time()
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    capture_filename = "test_mqtt_publish_qos1_TC19272"
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
        time.sleep(1)

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
                try:
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                except:
                    time.sleep(5)
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)

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


@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(300, 30000, 0.5)])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_rx_TC19283(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
):
    current_time = time.time()
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    capture_filename = "test_mqtt_rx_TC19283"
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

    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
        logger.info(f"'{wifi_dut.name}' is connected to MQTT server")

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

                try:
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                except:
                    time.sleep(5)
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)

    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()

    logger.info(f"total pkts received {len(msgs)}")
    count = 0
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    rx_file = "./reports/" + capture_filename + "_rx_file" + file_time_stamp + ".txt"
    if len(msgs):
        with open(rx_file, "w") as recv:
            for pkt in msgs:
                count = count + 1
                logger.info(
                    f"pkt no {count} -> topic name {pkt.topic}   message length {len(pkt.payload)} message {pkt.payload.decode()}")

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


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(60, 300)])
def test_mqtt_keep_alive_60_TC19248(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger, keep_alive_time, idle_time
):
    capture_filename = "test_mqtt_keep_alive_60_TC19248"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

    # DUT connects to MQTT server
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                           keepalive_interval=keep_alive_time)
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

    if (not len(timestamp)) and (len(mqtt_capture_list)):
        logger.info(f"MQTT-ping packets are not captured in the sniffer")
        assert 0, "MQTT-ping packets are not captured in the sniffer"

    if len(timestamp):
        for count in range(0, len(timestamp) - 1):
            time_diff = float(timestamp[count + 1]) - float(timestamp[count])
            if time_diff > (4 + keep_alive_time):
                logger.info(f"MQTT-KEEP alive packets are not sending every {keep_alive_time}sec on {count + 1} time")
        logger.info(
            f"Number of MQTT-KEEP alive packets sent->{len(timestamp)} while the test has been running for "
            f"{idle_time} sec when keep alive time configured is {keep_alive_time}")

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(120, 600)])
def test_mqtt_keep_alive_120_TC19249(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger, keep_alive_time, idle_time
):
    capture_filename = "test_mqtt_keep_alive_120_TC19249"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

    # DUT connects to MQTT server
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                           keepalive_interval=keep_alive_time)
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

    if (not len(timestamp)) and (len(mqtt_capture_list)):
        logger.info(f"MQTT-ping packets are not captured in the sniffer")
        assert 0, "MQTT-ping packets are not captured in the sniffer"

    if len(timestamp):
        for count in range(0, len(timestamp) - 1):
            time_diff = float(timestamp[count + 1]) - float(timestamp[count])
            if time_diff > (4 + keep_alive_time):
                logger.info(f"MQTT-KEEP alive packets are not sending every {keep_alive_time}sec on {count + 1} time")
        logger.info(
            f"Number of MQTT-KEEP alive packets sent->{len(timestamp)} while the test has been running for "
            f"{idle_time} sec when keep alive time configured is {keep_alive_time}")

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(300, 1200)])
def test_mqtt_keep_alive_300_TC19250(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger, keep_alive_time, idle_time
):
    capture_filename = "test_mqtt_keep_alive_300_TC19250"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

    # DUT connects to MQTT server
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                           keepalive_interval=keep_alive_time)
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

    if (not len(timestamp)) and (len(mqtt_capture_list)):
        logger.info(f"MQTT-ping packets are not captured in the sniffer")
        assert 0, "MQTT-ping packets are not captured in the sniffer"

    if len(timestamp):
        for count in range(0, len(timestamp) - 1):
            time_diff = float(timestamp[count + 1]) - float(timestamp[count])
            if time_diff > (4 + keep_alive_time):
                logger.info(f"MQTT-KEEP alive packets are not sending every {keep_alive_time}sec on {count + 1} time")
        logger.info(
            f"Number of MQTT-KEEP alive packets sent->{len(timestamp)} while the test has been running for "
            f"{idle_time} sec when keep alive time configured is {keep_alive_time}")

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(0, 120)])
def test_mqtt_keep_alive_disable_TC19251(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger, keep_alive_time, idle_time
):
    capture_filename = "test_mqtt_keep_alive_disable_TC19251"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

    # DUT connects to MQTT server
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                           keepalive_interval=keep_alive_time)
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


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
def test_mqtt_connect_clean_session_0_TC19289(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger
):
    capture_filename = "test_mqtt_connect_clean_session_0_TC19289"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

    # DUT connects to MQTT server
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, clean_session=0
                                                           )
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(1)
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    mqtt_capture_list = get_mqtt_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["mqtt"], capture_filename)
    if not len(mqtt_capture_list):
        logger.info(f"MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")
        assert 0, "MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the sniffer " \
                  "file "

    flag = False
    clean_session = False
    for count in mqtt_capture_list:
        if "Connect Command" in count[0]:
            flag = True
            mqtt_fields = count[0].split("\n")
            for field in mqtt_fields:
                if "Clean Session Flag:" in field:
                    if field.split(":")[1].strip() == "Set":
                        clean_session = True
                    break
    if not flag:
        logger.info(f"MQTT-CONNECT packet is not captured")
        assert 0, f"MQTT-CONNECT packet is not captured"
    assert clean_session == True, f"DUT is not sending MQTT-CONNECT PKT with clean session flag in mqtt header"
    logger.info("DUT sent MQTT-CONNECT PKT with clean session flag in mqtt header")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.mqtt_server("raspi_mosquitto_auth")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case should produce error 0X0036 as username or password is more than 60 bytes
def test_mqtt_check_error_0X0036_C19275(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger
        ):
    # The api generates 100 bytes of random data
    username = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    capture_filename = "test_mqtt_check_error_0X0036_C19275"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    logger.info(f"username is {username}")
    with pytest.raises(WlanError) as exc_info:
        # DUT tries to connect to mqtt server
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, username=username)
        logger.info(f"DUT sent {exc_info.value.error_code} code when the username or password is more than 60 bytes")
    assert exc_info.value.error_code == 0X0036, "DUT sent wrong error code, expected is 0X0036"

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_reconnection_MQTT_server_C19278(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, wifi_client,
):
    try:
        topic1 = "mytesttopic/1"
        capture_filename = "test_reconnection_MQTT_server_C19278"
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        logger.info("\n\n*******Both DUT and third-party mqtt client connects to MQTT server*******")
        for iteration in range(1, 3):
            port = 1883
            if iteration == 2:
                port = 1885
            wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, client_port=port)
            mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
            time.sleep(5)
            if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
                wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic1)
            interface = 'eth1'
            if iteration == 1:
                logger.info("\n\n*********==========>>>>>>>>Disable Ethernet Adaptor\n\n")
                wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {interface} down")
                time.sleep(300)
                events = wifi_dut.interfaces.mqtt.get_async_events()
                if len(events):
                    for event in events:
                        if event.event_type == RS9116AsyncEventType.MQTT_REMOTE_TERMINATE:
                            break
                logger.info("\n\nEnable Ethernet Adaptor<<<<<<<<*******===========\n\n")
                wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {interface} up")
                time.sleep(20)
        wifi_dut.interfaces.wifi.leave()
        logger.info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Sniffer is going stop capture")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
    finally:
        wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {interface} up")
        logger.info("\n\nEnabling Ethernet Adaptor<<<<<<<<*******===========")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_reconnection_MQTT_server_with_same_client_port_C19276(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, wifi_client,
):
    try:
        topic1 = "mytesttopic/1"
        capture_filename = "test_reconnection_MQTT_server_with_same_client_port_C19276"
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        logger.info("\n\n*******Both DUT and third-party mqtt client connects to MQTT server*******")
        for iteration in range(1, 3):
            wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
            mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
            time.sleep(5)
            if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
                wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic1)
            interface = 'eth1'
            if iteration == 1:
                logger.info("\n\n*********==========>>>>>>>>Disable Ethernet Adaptor\n\n")
                wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {interface} down")
                time.sleep(300)
                events = wifi_dut.interfaces.mqtt.get_async_events()
                if len(events):
                    for event in events:
                        if event.event_type == RS9116AsyncEventType.MQTT_REMOTE_TERMINATE:
                            break
                logger.info("\n\nEnable Ethernet Adaptor<<<<<<<<*******===========\n\n")
                wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {interface} up")
                time.sleep(20)
        logger.info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Sniffer is going stop capture")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        wifi_dut.interfaces.wifi.leave()
    finally:
        logger.info("\n\nEnabling Ethernet Adaptor<<<<<<<<*******===========")
        wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {interface} up")
        time.sleep(5)


@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
def test_mqtt_check_error_0X0030_C19280(wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger):
# The test case checks error 0X0030 as topic length is greater than or less than the topic name given in the command
    topic1 = "mytesttopic"
    # The api returns 100 bytes of random data
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    capture_filename = "test_mqtt_check_error_0X0030_C19280"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    # DUT connects to MQTT server after execution of below api
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
    # mqtt-client connects to MQTT server after execution of below api
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
    time.sleep(5)
    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic1)
    time.sleep(1)
    # publish a message with the dut
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, message1.encode(), custom_length=True, topic_custom_length=30, fire_forget=False)
        err_val = exc_info.value.error_code
        logger().info(f"DUT sent {err_val} code when Topic length is greater than or less than topic name")
        assert exc_info.value.error_code == 0X0030, "DUT sent wrong error code, expected is 0X0030"
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()