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
import random
import string


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
        # "client_cert":
        # "client_key":
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
