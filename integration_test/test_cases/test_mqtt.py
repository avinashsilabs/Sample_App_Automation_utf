import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType, RS9116AsyncEventType,
)
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.mqtt.client import MqttClientInterface

# Mark all tests in this module with 'framework_integration_test'
# and use fixture parameterize_mqtt_server
pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.wifi_access_point("raspi_wifi"),
    pytest.mark.mqtt_server("raspi_mosquitto")
]


@pytest.fixture(
    params=[
        ("raspi_mosquitto", "raspi_wifi"),
        ("raspi_mosquitto_auth", "raspi_wifi"),
        ("raspi_mosquitto_tls", "raspi_wifi"),
        ("static_mqtt_broker", "dlink810_ap"),
    ]
)
def parameterize_mqtt_server(harness, request):
    request.applymarker(pytest.mark.mqtt_server(request.param[0]))
    request.applymarker(pytest.mark.wifi_access_point(request.param[1]))


@pytest.mark.test_src_map_id('SM11895')
def test_mqtt_server_and_linux_client(
    mqtt_server, mqtt_client, wifi_client, wifi_access_point
):
    if wifi_client != wifi_access_point:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
        wifi_client.interfaces.wifi.start_ip()

    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt
    )
    # Wait up to 5 seconds for connection
    sw = Stopwatch()
    while sw.elapsed_sec < 5:
        time.sleep(0.1)
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe("my test topic")
            break
    else:
        assert (
            mqtt_client.interfaces.mqtt.mqtt_client_is_connected
        ), f"Client '{mqtt_client.name}' did not connect to MQTT server"

    mqtt_client.interfaces.mqtt.mqtt_client_publish("my test topic", b"12345")
    # wait up to 10 sec for expected messages to be received
    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1
    assert msgs[0].topic == "my test topic"
    assert msgs[0].payload == b"12345"


@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
    },
)
@pytest.mark.test_src_map_id('SM11900')
def test_mqtt_dut(
    mqtt_server, mqtt_client, wifi_client, wifi_access_point, wifi_dut, mqtt_dut, logger
):
    if wifi_client != wifi_access_point:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
        wifi_client.interfaces.wifi.start_ip()

    # load SSL CA cert if necessary
    if mqtt_server.interfaces.mqtt.tls_enabled:
        wifi_dut.interfaces.wifi.set_ssl_certificate(
            RS9116CertificateType.SSLCACertificate,
            mqtt_server.interfaces.mqtt.tls_ca_chain,
        )

    # for both dut and another wifi client, connect to the MQTT server
    client_devices = [mqtt_dut, mqtt_client]
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
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
    mqtt_dut.interfaces.mqtt.mqtt_client_publish("mytesttopic/1", "12345".encode())
    # publish a message with the other client
    mqtt_client.interfaces.mqtt.mqtt_client_publish("mytesttopic/2", "123456".encode())

    for device in client_devices:
        # allow some time for both clients to receive all messages
        sw = Stopwatch()
        msgs = []
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = device.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 2:
                break

        assert len(msgs) == 2
        expected_messages = [
            MqttClientInterface.MqttMessage(
                "mytesttopic/1", "12345".encode(), 0, False, False, 0
            ),
            MqttClientInterface.MqttMessage(
                "mytesttopic/2", "123456".encode(), 0, False, False, 0
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

    events = mqtt_dut.interfaces.wifi.get_async_events()
    assert len([ev for ev in events if ev.event_type == RS9116AsyncEventType.MQTTMessage]) == 2
    events = mqtt_dut.interfaces.wifi.get_async_events()
    assert len([ev for ev in events if ev.event_type == RS9116AsyncEventType.MQTTMessage]) == 0


# @pytest.mark.skip
# @pytest.mark.dut("rs9116_sapi")
# @pytest.mark.mqtt_server("raspi_mosquitto")
# @pytest.mark.wifi_access_point("raspi_wifi")
# @pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
#         "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
#     },
# )
# def test_mqtt_sapi(
#     mqtt_server, mqtt_client, wifi_client, wifi_access_point, wifi_dut, mqtt_dut, logger
# ):
#     if wifi_client != wifi_access_point:
#         wifi_client.interfaces.wifi.join_ap(wifi_access_point)
#         wifi_client.interfaces.wifi.start_ip()
#
#     # load SSL CA cert if necessary
#     if mqtt_server.interfaces.mqtt.tls_enabled:
#         wifi_dut.interfaces.wifi.set_ssl_certificate(
#             RS9116CertificateType.SSLCACertificate,
#             mqtt_server.interfaces.mqtt.tls_ca_chain,
#         )
#
#     wifi_dut.interfaces.wifi.ping(wifi_dut.interfaces.wifi.ip.gateway)
#
#     # for both dut and another wifi client, connect to the MQTT server
#     client_devices = [mqtt_client, mqtt_dut]
#     for device in client_devices:
#         device.interfaces.mqtt.mqtt_client_connect_to_server(
#             mqtt_server.interfaces.mqtt
#         )
#
#     # allow some time for both clients to connect before sending messages
#     for device in [mqtt_client]:
#         sw = Stopwatch()
#         while sw.elapsed_sec < 5:
#             time.sleep(0.1)
#             if device.interfaces.mqtt.mqtt_client_is_connected:
#                 device.interfaces.mqtt.mqtt_client_subscribe("mytesttopic/#")
#                 logger.info(f"'{device.name}' is connected to MQTT server")
#                 break
#         else:
#             assert (
#                 device.interfaces.mqtt.mqtt_client_is_connected
#             ), f"Client '{device.name}' did not connect to MQTT server"
#
#     # publish a message with the dut
#     mqtt_dut.interfaces.mqtt.mqtt_client_publish("mytesttopic/1", "12345".encode())
#
#     for device in [mqtt_client]:
#         # allow some time for both clients to receive all messages
#         sw = Stopwatch()
#         msgs = []
#         while sw.elapsed_sec < 10:
#             time.sleep(0.1)
#             msgs = device.interfaces.mqtt.mqtt_client_get_received_messages()
#             if len(msgs) == 1:
#                 break
#
#         assert len(msgs) == 1
#         assert msgs[0].topic == "mytesttopic/1"
#         assert msgs[0].payload == "12345".encode()
