import random
import string
import time

import pytest

from utf.interfaces.mqtt.client import MqttClientInterface
from utf.utils.logger import Loggable
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.devices.rs911x import RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116CertificateType, \
    RS9116AsyncEventType, RS9116MqttQos


class MqttClientPublish(ThreadBase, Loggable):
    def __init__(self, wifi_dut, mqtt_client, topic, message, qos):
        super().__init__()
        self.wifi_dut =wifi_dut
        self.mqtt_client = mqtt_client
        self.topic = topic
        self.message = message
        self.qos = qos

    def run(self):
        self.logger.info(f"*** publishing a message with the third-party mqtt client")
        self.logger.info(f"client_topic:'{self.topic}',qos:'{self.qos}',client_message '{self.message}'")
        self.mqtt_client.interfaces.mqtt.mqtt_client_publish(self.topic, self.message.encode(), qos= self.qos)
        time.sleep(1)


class MqttDutPublish(ThreadBase, Loggable):
    def __init__(self, wifi_dut, mqtt_client, topic, message, qos):
        super().__init__()
        self.mqtt_client = mqtt_client
        self.wifi_dut = wifi_dut
        self.topic = topic
        self.qos = qos
        self.message = message

    def run(self):
        self.logger.info("publishing a message with the dut ")
        self.logger.info(f"dut_topic:'{self.topic}', qos:'{self.qos}',dut_message '{self.message}'")
        self.wifi_dut.interfaces.mqtt.mqtt_client_publish(self.topic, self.message.encode(), qos=self.qos)


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
@pytest.mark.test_src_map_id('SM11904')
def test_mqtt_dut_thread(
    mqtt_server, mqtt_client, wifi_client, wifi_access_point, wifi_dut, mqtt_dut, logger
):
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))

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

    t1 = MqttClientPublish(wifi_dut, mqtt_client, topic=topic1, message=message1, qos=RS9116MqttQos.QOS1)
    t2 = MqttDutPublish(wifi_dut, mqtt_client, topic=topic2, message=message2, qos=RS9116MqttQos.QOS1)

    t1.start()
    t2.start()

    t1.wait_for_exit()
    t2.wait_for_exit()

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
                topic1, message1.encode(), 0, False, False, 0
            ),
            MqttClientInterface.MqttMessage(
                topic2, message2.encode(), 0, False, False, 0
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