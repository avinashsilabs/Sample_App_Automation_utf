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
    RS9116MqttQos,
    MQTTHeaderLength
    )
from utils.stopwatch import Stopwatch
import string
import filecmp
import os
import random
from threading import Thread

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Load ssl certificates into the DUT
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Open MQTT server in the Raspberry pi
        6. Connect to the MQTT server from the DUT
        7. Connect to the MQTT server from the Raspberry pi
        8. Send or receive data on MQTT and verify packet loss tests 
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

Note: The test cases added in the file works only in AT mode
"""


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
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks whether the DUT is able to connect to MQTT server over SSL when authentication feature is enabled
def test_mqtt_authentication_ssl_testcase18(
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
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_rx_after_rejoin_ssl_testcase31(
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
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_publish_while_rejoin_ssl_testcase34(
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
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_rx_ssl_testcase45(
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
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1200, 1024000, 0.5)])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_publish_1mb_file_ssl_testcase46(
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
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1370, 102400, 0.5)])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_publish_max_len_ssl_testcase47(
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
    publish_len = (1370 - len(topic1) - MQTTHeaderLength.Length)
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
        "ca_cert": "ca_ecdsa.crt"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1370, 102400, 0.5)])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto_tls_ecdsa")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_publish_max_len_ssl_ecdsa_testcase50(
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
    publish_len = (1370 - len(topic1) - MQTTHeaderLength.Length)
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


# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#         "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
#         "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
#         "rejoin_max_retry": 10,
#         "scan_interval": 6,
#         "beacon_missed_count": 40,
#         "first_time_retry": 0,
#         "ca_cert": "AWS-IoT-root-CA.crt",
#         "client_cert": "python-thing-certificate.pem.crt",
#         "client_key": "python-thing-private.pem.key"
#
#         },
#     )
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
# @pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# @pytest.mark.mqtt_server("static_mqtt_broker")
# # The test case checks mqtt connection, subscribe and publish feature when mqtt qos associated is qos0
# def test_mqtt_qos1_aws_connect_sub_publish_testcase_28(
#         mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
#         ):
#     topic_wild = "mytesttopic/#"
#     topic1 = "mytesttopic/1"
#     topic2 = "mytesttopic/2"
#     # The api returns 100 bytes of random data
#     message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
#     # The api returns 200 bytes of random data
#     message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
#     # DUT connects to AP after join_ap API is executed
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     # DUT gets ipaddress through DHCP process after start_ip API is executed
#     wifi_dut.interfaces.wifi.start_ip()
#     # The below api puts DUT to power save
#     wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
#     wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
#     client_devices = [wifi_dut, mqtt_client]
#     # Both DUT and third-party mqtt client connects to MQTT server
#     for device in client_devices:
#         device.interfaces.mqtt.mqtt_client_connect_to_server(
#             mqtt_server.interfaces.mqtt
#             )
#
#     # Both DUT and third-party mqtt client subscribe on topic mytesttopic/#
#     for device in client_devices:
#         sw = Stopwatch()
#         while sw.elapsed_sec < 5:
#             time.sleep(0.1)
#             if device.interfaces.mqtt.mqtt_client_is_connected:
#                 device.interfaces.mqtt.mqtt_client_subscribe(topic_wild)
#                 logger.info(f"'{device.name}' is connected to MQTT server")
#                 break
#         else:
#             assert (
#                 device.interfaces.mqtt.mqtt_client_is_connected
#             ), f"Client '{device.name}' did not connect to MQTT server"
#
#     # publish a message with the dut
#     wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, message1.encode())
#     # publish a message with the third-party mqtt client
#     mqtt_client.interfaces.mqtt.mqtt_client_publish(topic2, message2.encode())
#
#     for device in client_devices:
#         # allow some time for both clients to receive all messages
#         sw = Stopwatch()
#         msgs = []
#         while sw.elapsed_sec < 10:
#             time.sleep(0.1)
#             # Both DUT and mqtt client receive messages
#             msgs = device.interfaces.mqtt.mqtt_client_get_received_messages()
#             if len(msgs) == 2:
#                 break
#
#         assert len(msgs) == 2, "No message is received by DUT and mqtt-client"
#         assert msgs[0].topic == topic1, "No message received by DUT on subscribed topic"
#         assert msgs[0].payload.decode() == message1, "No message is received by DUT on subscribed topic or message " \
#                                                      "received is wrong"
#         assert msgs[0].qos == RS9116MqttQos.QOS0, "DUT received message with wrong QOS. expected is QOS0"
#         assert msgs[1].topic == topic2, "No message received by mqtt-client on subscribed topic"
#         assert msgs[1].qos == RS9116MqttQos.QOS0, "DUT sent message with wrong QOS. expected is QOS0"
#         assert msgs[1].payload.decode() == message2, "No message is received by mqtt-client on subscribed topic or " \
#                                                      "message " \
#                                                      "received is wrong"
#
#     # The API returns asynchronous messages received by DUT
#     events = wifi_dut.interfaces.wifi.get_async_events()
#     assert len(events) == 2
#     # The API returns asynchronous messages received by DUT
#     events = wifi_dut.interfaces.wifi.get_async_events()
#     assert len(events) == 0


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
        "ca_cert": "ca_ecdsa.crt"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto_tls_ecdsa")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_rx_ssl_ecdsa_testcase51(
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
