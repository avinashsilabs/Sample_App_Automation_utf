# Test author: Vinod.G
# Test suite: MQTT_INTERNAL
import time
import pytest
from devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116AsyncEventType,
    RS9116PowerSaveModes,
    RS9116MqttQos
    )
from utils.stopwatch import Stopwatch
import string
from interfaces.wifi import WlanError
import filecmp
import os
import random
from threading import Thread
from utils import mac_address_to_string
from typing import Dict

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


def get_mqtt_list(wifi_sniffer, decryption_key: str, print_layers: list, mode=0) -> Dict[str, int]:
    mqtt_capture_list = []
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()

            if layer_name in print_layers:
                mqtt_layer = str(layer)
                mqtt_capture_list.append(tuple([mqtt_layer, packet.sniff_timestamp]))
    return mqtt_capture_list


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks mqtt connection, subscribe and publish feature when mqtt qos associated is qos0
def test_mqtt_qos0_connect_sub_publish_testcase_14(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    # The api returns 100 bytes of random data
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    # The api returns 200 bytes of random data
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    # Both DUT and third-party mqtt client connects to MQTT server
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    # Both DUT and third-party mqtt client subscribe on topic mytesttopic/#
    for device in client_devices:
        sw = Stopwatch()
        while sw.elapsed_sec < 5:
            time.sleep(0.1)
            if device.interfaces.mqtt.mqtt_client_is_connected:
                device.interfaces.mqtt.mqtt_client_subscribe(topic_wild)
                logger.info(f"'{device.name}' is connected to MQTT server")
                break
        else:
            assert (
                device.interfaces.mqtt.mqtt_client_is_connected
            ), f"Client '{device.name}' did not connect to MQTT server"

    # publish a message with the dut
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, message1.encode())
    # publish a message with the third-party mqtt client
    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic2, message2.encode())

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
        assert msgs[0].qos == RS9116MqttQos.QOS0, "DUT received message with wrong QOS. expected is QOS0"
        assert msgs[1].topic == topic2, "No message received by mqtt-client on subscribed topic"
        assert msgs[1].qos == RS9116MqttQos.QOS0, "DUT sent message with wrong QOS. expected is QOS0"
        assert msgs[1].payload.decode() == message2, "No message is received by mqtt-client on subscribed topic or " \
                                                     "message " \
                                                     "received is wrong"

    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 2
    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 0


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks mqtt connection, subscribe and publish feature when mqtt qos associated is qos1
def test_mqtt_qos1_connect_sub_publish_testcase_15(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    # The api returns 100 bytes of random data
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    # The api returns 200 bytes of random data
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    # Both DUT and third-party mqtt client connects to MQTT server
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

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
    # publish a message with the third-party mqtt client
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


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks DUT behavior when DUT is trying to connect to MQTT server, but server is not responding
def test_mqtt_invalid_server_testcase2(
        mqtt_server, wifi_access_point, wifi_dut, logger
        ):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

    with pytest.raises(WlanError) as exc_info:
        # After execution of below api DUT connects to MQTT server
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                               mqtt_server="192.168.100.50")
    assert exc_info.value.error_code == 0xFF87, "DUT sent wrong error code, expected is 0xFF87"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks DUT behavior when DUT is tyring to connect to MQTT server with client id, but the same client
# id is already being used by another mqtt client
def test_mqtt_common_clientid_testcase_5(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    mqtt_client_id = "mqtt_908765436789876589"
    topic = "mytesttopic/#"
    # DUT connects to MQTT server
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, client_id=mqtt_client_id)
    # mqtt-client connects to MQTT server
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, client_id=mqtt_client_id)
    time.sleep(5)
    # The API returns asynchronous messages received by DUT
    wifi_dut.interfaces.wifi.get_async_events()
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic)
    assert exc_info.value.error_code == 0x021, "DUT sent wrong error code, expected is 0x0021"
    wifi_dut.interfaces.mqtt._mqtt_client_connected = False


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.mqtt_server("raspi_mosquitto_auth")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks mqtt connection, subscribe and publish feature when password based authentication feature is
# enabled on mqtt server
def test_mqtt_authentication_testcase6(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    # The api returns 100 bytes of random data
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    # The api returns 200 bytes of random data
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    # Both DUT and third-party mqtt client connects to MQTT server
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

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
    # publish a message with the third-party mqtt client
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


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.mqtt_server("raspi_mosquitto_auth")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks DUT behavior when trying to connect to MQTT server with wrong credentials
def test_mqtt_authentication_wrong_cred_testcase7(
        mqtt_server, wifi_access_point, wifi_dut, logger
        ):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    with pytest.raises(RuntimeError) as exc_info:
        # After execution of below api DUT connects to MQTT server
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                               username="wrong_user",
                                                               password="wrong_password")
    logger.info(exc_info.value)
    assert str(exc_info.value) == "MQTT Connection error 0x5: The Client is not authorized to connect", "DUT sent " \
                                                                                                        "wrong " \
                                                                                                        "error code, " \
                                                                                                        "expected is " \
                                                                                                        "0x0005 "


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "wifi_powersave_disable", "mqtt_disconnect"])
# The test case checks mqtt publish message with retain option
def test_mqtt_retain_testcase_16(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
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
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)

    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        #  mqtt client receives messages
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by mqtt-client on subscribed topic"
    assert msgs[0].topic == topic
    assert msgs[0].payload == message2.encode()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks mqtt publish message with retain option
def test_mqtt_delete_retain_message_testcase17(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
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
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)

    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        #  mqtt client receives messages
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 0


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# the test case checks MQTT unsubscribe functionality
def test_mqtt_unsubscribe_testcase_20(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
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


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 20,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# the test case runs mqtt sequence multiple times
def test_mqtt_sequence_testcase_22(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
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


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks mqtt functionality after DUT is connected to AP second time
def test_mqtt_reconnect_testcase_23(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
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
        # DUT connects to AP after join_ap API is executed
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api puts DUT to power save
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# DUT functionality when trying to connect to MQTT server with client-id NULL
def test_mqtt_common_clientid_null_testcase_29(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    # The api returns 100 bytes of random data
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    # The api returns 200 bytes of random data
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
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
    # publish a message with the third-party mqtt client
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


def ApWirelessOff(wifi_access_point, wait_time, logger):
    time.sleep(wait_time)
    logger.info(f"Disabling Wireless in AP")
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(1)
    logger.info(f"Enabling Wireless in AP")
    wifi_access_point.interfaces.wifi.start_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_tx_after_rejoin_testcase24(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
        ):
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    with open("temp.txt", "w") as temp:
        temp.write(temp_buffer)

    client_devices = [wifi_dut, mqtt_client]

    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(5)

    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
        logger.info(f"'{mqtt_client.name}' is connected to MQTT server")

    send_count = 0
    ap_power_off = 0
    send_pkts = int((total_bytes / publish_len))

    with open("temp.txt", "r") as temp:
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
                    thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 1, logger), )
                    thread.start()
                try:
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                except:
                    time.sleep(120)
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                send_count = send_count + 1
                if send_count == int((send_pkts / 4)):
                    ap_power_off = 1

    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

    if len(msgs):
        with open("mqtt_rx.txt", "w") as recv:
            for pkt in msgs:
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists("mqtt_rx.txt"):
        logger.info("No MQTT data received at receiver")

    result = filecmp.cmp("temp.txt", "mqtt_rx.txt", shallow=False)
    if os.path.exists("mqtt_rx.txt"):
        os.remove("mqtt_rx.txt")
    if os.path.exists("temp.txt"):
        os.remove("temp.txt")
    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_init_after_rejoin_fail_testcase25(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
        ):
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    with open("temp.txt", "w") as temp:
        temp.write(temp_buffer)

    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt
        )

    time.sleep(1)

    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(120)

    wifi_access_point.interfaces.wifi.start_ap()
    wifi_dut.interfaces.wifi.initialized = False
    wifi_dut.interfaces.wifi.associated = False
    time.sleep(2)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

    client_devices = [wifi_dut, mqtt_client]

    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(5)
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
        logger.info(f"'{mqtt_client.name}' is connected to MQTT server")

    with open("temp.txt", "r") as temp:
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

    if len(msgs):
        with open("mqtt_rx.txt", "w") as recv:
            for pkt in msgs:
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists("mqtt_rx.txt"):
        logger.info("No MQTT data received at receiver")

    result = filecmp.cmp("temp.txt", "mqtt_rx.txt", shallow=False)
    if os.path.exists("mqtt_rx.txt"):
        os.remove("mqtt_rx.txt")
    if os.path.exists("temp.txt"):
        os.remove("temp.txt")
    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(100, 102400, 0.5)])
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_rx_after_rejoin_testcase30(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
        ):
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    with open("temp.txt", "w") as temp:
        temp.write(temp_buffer)

    client_devices = [wifi_dut, mqtt_client]

    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(1)

    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
        logger.info(f"'{wifi_dut.name}' is connected to MQTT server")

    send_count = 0
    ap_power_off = 0
    send_pkts = int((total_bytes / publish_len))

    with open("temp.txt", "r") as temp:
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
                    thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 1, logger), )
                    thread.start()
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

    if len(msgs):
        with open("mqtt_rx.txt", "w") as recv:
            for pkt in msgs:
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists("mqtt_rx.txt"):
        logger.info("No MQTT data received at receiver")

    result = filecmp.cmp("temp.txt", "mqtt_rx.txt", shallow=False)
    if os.path.exists("mqtt_rx.txt"):
        os.remove("mqtt_rx.txt")
    if os.path.exists("temp.txt"):
        os.remove("temp.txt")
    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_publish_qos1_testcase32(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
        ):
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    with open("temp.txt", "w") as temp:
        temp.write(temp_buffer)

    client_devices = [wifi_dut, mqtt_client]

    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(5)

    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
        logger.info(f"'{mqtt_client.name}' is connected to MQTT server")

    with open("temp.txt", "r") as temp:
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

    if len(msgs):
        with open("mqtt_rx.txt", "w") as recv:
            for pkt in msgs:
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists("mqtt_rx.txt"):
        logger.info("No MQTT data received at receiver")

    result = filecmp.cmp("temp.txt", "mqtt_rx.txt", shallow=False)
    if os.path.exists("mqtt_rx.txt"):
        os.remove("mqtt_rx.txt")
    if os.path.exists("temp.txt"):
        os.remove("temp.txt")
    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(300, 30000, 0.5)])
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_rx_testcase43(
        mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
        ):
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    with open("temp.txt", "w") as temp:
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

    with open("temp.txt", "r") as temp:
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
    if len(msgs):
        with open("mqtt_rx.txt", "w") as recv:
            for pkt in msgs:
                count = count + 1
                logger.info(
                    f"pkt no {count} -> topic name {pkt.topic}   message length {len(pkt.payload)} message {pkt.payload}")
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists("mqtt_rx.txt"):
        logger.info("No MQTT data received at receiver")

    result = filecmp.cmp("temp.txt", "mqtt_rx.txt", shallow=False)
    if os.path.exists("mqtt_rx.txt"):
        os.remove("mqtt_rx.txt")
    if os.path.exists("temp.txt"):
        os.remove("temp.txt")
    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(60, 300)])
def test_mqtt_keep_alive_60_testcase_8(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger, keep_alive_time, idle_time
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]

    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )

    mac_address = mac_address_to_string(wifi_dut.interfaces.wifi.mac_address)

    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )

    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

    # DUT connects to MQTT server
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                           keepalive_interval=keep_alive_time)
    time.sleep(idle_time)
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(1)
    timestamp = []
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    mqtt_capture_list = get_mqtt_list(wifi_sniffer, decryption_key, ["mqtt"])
    if not len(mqtt_capture_list):
        logger.info(f"MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")
    for count in mqtt_capture_list:
        if "Ping Request" in count[0]:
            timestamp.append(count[1])

    if (not len(timestamp)) and (len(mqtt_capture_list)):
        logger.info(f"MQTT-ping packets are not captured in the sniffer")

    if len(timestamp):
        for count in range(0, len(timestamp) - 1):
            time_diff = float(timestamp[count + 1]) - float(timestamp[count])
            if time_diff > (4 + keep_alive_time):
                logger.info(f"MQTT-KEEP alive packets are not sending every {keep_alive_time}sec on {count} time")
            logger.info(
                f"Number of MQTT-KEEP alive packets sent->{len(timestamp)}, while the test has been running for {idle_time} sec")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(120, 600)])
def test_mqtt_keep_alive_120_testcase_9(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger, keep_alive_time, idle_time
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]

    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )

    mac_address = mac_address_to_string(wifi_dut.interfaces.wifi.mac_address)

    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )

    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

    # DUT connects to MQTT server
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                           keepalive_interval=keep_alive_time)
    time.sleep(idle_time)
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(1)
    timestamp = []
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    mqtt_capture_list = get_mqtt_list(wifi_sniffer, decryption_key, ["mqtt"])
    if not len(mqtt_capture_list):
        logger.info(f"MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")
    for count in mqtt_capture_list:
        if "Ping Request" in count[0]:
            timestamp.append(count[1])

    if (not len(timestamp)) and (len(mqtt_capture_list)):
        logger.info(f"MQTT-ping packets are not captured in the sniffer")

    if len(timestamp):
        for count in range(0, len(timestamp) - 1):
            time_diff = float(timestamp[count + 1]) - float(timestamp[count])
            if time_diff > (4 + keep_alive_time):
                logger.info(f"MQTT-KEEP alive packets are not sending every {keep_alive_time}sec on {count} time")
            logger.info(
                f"Number of MQTT-KEEP alive packets sent->{len(timestamp)}, while the test has been running for {idle_time} sec")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(300, 1200)])
def test_mqtt_keep_alive_300_testcase_10(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger, keep_alive_time, idle_time
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]

    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )

    mac_address = mac_address_to_string(wifi_dut.interfaces.wifi.mac_address)

    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )

    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

    # DUT connects to MQTT server
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                           keepalive_interval=keep_alive_time)
    time.sleep(idle_time)
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(1)
    timestamp = []
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    mqtt_capture_list = get_mqtt_list(wifi_sniffer, decryption_key, ["mqtt"])
    if not len(mqtt_capture_list):
        logger.info(f"MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")
    for count in mqtt_capture_list:
        if "Ping Request" in count[0]:
            timestamp.append(count[1])

    if (not len(timestamp)) and (len(mqtt_capture_list)):
        logger.info(f"MQTT-ping packets are not captured in the sniffer")

    if len(timestamp):
        for count in range(0, len(timestamp) - 1):
            time_diff = float(timestamp[count + 1]) - float(timestamp[count])
            if time_diff > (4 + keep_alive_time):
                logger.info(f"MQTT-KEEP alive packets are not sending every {keep_alive_time}sec on {count} time")
            logger.info(
                f"Number of MQTT-KEEP alive packets sent->{len(timestamp)}, while the test has been running for {idle_time} sec")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(0, 120)])
def test_mqtt_keep_alive_disable_testcase_11(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger, keep_alive_time, idle_time
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]

    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )

    mac_address = mac_address_to_string(wifi_dut.interfaces.wifi.mac_address)

    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )

    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

    # DUT connects to MQTT server
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                           keepalive_interval=keep_alive_time)
    time.sleep(idle_time)
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(1)
    timestamp = []
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    mqtt_capture_list = get_mqtt_list(wifi_sniffer, decryption_key, ["mqtt"])
    if not len(mqtt_capture_list):
        logger.info(f"MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")
    for count in mqtt_capture_list:
        if "Ping Request" in count[0]:
            timestamp.append(count[1])
    assert len(timestamp) == 0, f"DUT is sending MQTT-KEEP alive packets even though feature is disabled"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
def test_mqtt_connect_clean_session_0_testcase_49(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]

    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )

    mac_address = mac_address_to_string(wifi_dut.interfaces.wifi.mac_address)

    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )

    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

    # DUT connects to MQTT server
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, clean_session=0
                                                           )
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(1)
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    mqtt_capture_list = get_mqtt_list(wifi_sniffer, decryption_key, ["mqtt"])
    if not len(mqtt_capture_list):
        logger.info(f"MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")
        return
    flag = False
    clean_session = False
    for count in mqtt_capture_list:
        if "Connect Command" in count[0]:
            flag = True
            mqtt_fields = count[0].split("\n")
            for field in mqtt_fields:
                if "Clean Session Flag:" in field:
                    field.split(":")[1].strip() == "Set"
                    clean_session = True
                    break
    if not flag:
        logger.info(f"MQTT-CONNECT packet is not captured")
        return
    assert clean_session == True, f"DUT is not sending MQTT-CONNECT PKT with clean session flag in mqtt header"
