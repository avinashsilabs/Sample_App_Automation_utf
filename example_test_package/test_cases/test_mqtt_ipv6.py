import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType, RS9116AsyncEventType,
)
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.mqtt.client import MqttClientInterface


@pytest.mark.dut("rs9116_sapi")
# @pytest.mark.parametrize(("n", "expected"), [
#     pytest.param(1, 2, marks=pytest.mark.T1),
#     pytest.param(2, 3, marks=pytest.mark.T2),
#     (4, 5)
# ])
@pytest.mark.parametrize(("n"), [
    pytest.param(1,  marks=pytest.mark.mqtt_server("raspi_mosquitto_ipv6")),
    pytest.param(2,  marks=pytest.mark.mqtt_server("raspi_mosquitto_auth_ipv6")),
    pytest.param(3,  marks=pytest.mark.mqtt_server("raspi_mosquitto_tls_ipv6")),
])
#@pytest.mark.parametrize("mqtt_server", [@pytest.mark.mqtt_server("raspi_mosquitto_ipv6"), @pytest.mark.mqtt_server("raspi_mosquitto_ipv6")])
#@pytest.mark.mqtt_server("raspi_mosquitto_ipv6")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.DHCPv6Client,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
    },
)
def test_mqtt_using_mqttt_client(
    mqtt_server, mqtt_client, wifi_client, wifi_access_point, logger, n
):
    
    if wifi_client != wifi_access_point:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
        wifi_client.interfaces.wifi.start_ip()
        host_ip = wifi_client.interfaces.wifi.get_ip_address(version=6)
        logger.info(f"IP Address of Widi Client is :{host_ip}")
    time.sleep(2)
    # for wifi client, connect to the MQTT server
    client_devices = [mqtt_client]
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt, version=6
        )
    # allow some time for both clients to connect before sending messages
    for device in client_devices:
        sw = Stopwatch()
        while sw.elapsed_sec < 5:
            time.sleep(0.1)
            if device.interfaces.mqtt.mqtt_client_is_connected:
                device.interfaces.mqtt.mqtt_client_subscribe("mytesttopic/#")
                logger.info(f"'{device.name}' is connected to MQTT server")
                break
        else:
            assert (
                device.interfaces.mqtt.mqtt_client_is_connected
            ), f"Client '{device.name}' did not connect to MQTT server"
    # publish a message with the other client
    mqtt_client.interfaces.mqtt.mqtt_client_publish("mytesttopic/1", "123456".encode())

    for device in client_devices:
        # allow some time for both clients to receive all messages
        sw = Stopwatch()
        msgs = []
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = device.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break

        assert len(msgs) == 1
        expected_messages = [
            MqttClientInterface.MqttMessage(
                "mytesttopic/1", "123456".encode(), 0, False, False, 0
            ),
        ]
        for msg in msgs:
            found = False
            for expected_msg in expected_messages:
                if (
                    msg.topic == expected_msg.topic
                    and msg.payload == expected_msg.payload
                ):
                    found = True
            assert found

@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.DHCPv6Client,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
    },
)
@pytest.mark.mqtt_server("raspi_mosquitto_ipv6")
def test_mqtt_using_wifi_dut(
    mqtt_server, wifi_access_point, wifi_dut, wifi_client, logger
):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip(version=6)
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config, version=6)
    logger.info(f"IP Address of DUT is :{device_ip}")
    
    if wifi_client != wifi_access_point:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
        wifi_client.interfaces.wifi.start_ip()
        host_ip = wifi_client.interfaces.wifi.get_ip_address(version=6)
        logger.info(f"IP Address of Widi Client is :{host_ip}")
    
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 10
    time.sleep(2)
    
    # load SSL CA cert if necessary
    if mqtt_server.interfaces.mqtt.tls_enabled:
        wifi_dut.interfaces.wifi.set_ssl_certificate(
            RS9116CertificateType.SSLCACertificate,
            mqtt_server.interfaces.mqtt.tls_ca_chain,
        )
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi  
     # for dut connect to the MQTT server
    client_devices = [wifi_dut]
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt, version=6
        )
    # allow some time for both clients to connect before sending messages
    for device in client_devices:
        sw = Stopwatch()
        while sw.elapsed_sec < 5:
            time.sleep(0.1)
            if device.interfaces.mqtt.mqtt_client_is_connected:
                device.interfaces.mqtt.mqtt_client_subscribe("mytesttopic/#")
                logger.info(f"'{device.name}' is connected to MQTT server")
                break
        else:
            assert (
                device.interfaces.mqtt.mqtt_client_is_connected
            ), f"Client '{device.name}' did not connect to MQTT server"

    # publish a message with the dut
    wifi_dut.interfaces.mqtt.mqtt_client_publish("mytesttopic/1", "12345".encode())

    for device in client_devices:
        # allow some time for both clients to receive all messages
        sw = Stopwatch()
        msgs = []
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = device.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 2:
                break

        assert len(msgs) == 1
        expected_messages = [
            MqttClientInterface.MqttMessage(
                "mytesttopic/1", "12345".encode(), 0, False, False, 0
            )
        ]
        for msg in msgs:
            found = False
            for expected_msg in expected_messages:
                if (
                    msg.topic == expected_msg.topic
                    and msg.payload == expected_msg.payload
                ):
                    found = True
            assert found

    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len([ev for ev in events if ev.event_type == RS9116AsyncEventType.MQTTMessage]) == 1
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len([ev for ev in events if ev.event_type == RS9116AsyncEventType.MQTTMessage]) == 0
