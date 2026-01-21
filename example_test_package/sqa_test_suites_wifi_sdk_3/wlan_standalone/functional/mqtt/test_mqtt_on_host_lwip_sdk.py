import time
import pytest
import string
import re
import random
from datetime import datetime
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCertificateType,
    Si91xCertIdentifier,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xMqttQos,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xJoinFeatureBitMap,
    Si91xAesType,
    Si91xAesOperation,
    Si91xAesKeySize,
    Si91xKeyType,
    Si91xWrapIVMode,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import (
    AsyncEventIdentifiers,
)

Map_security = {
    "OPEN": 0,
    "WPA": 1,
    "WPA2": 2,
    "WEP": 3,
    "WPAEnterprise": 4,
    "WPA2Enterprise": 5,
    "WPA_WPA2_MIXED": 6,
    "WPA3": 7,
    "WPA3_TRANSITION": 8,
    "WPA3Enterprise": 9,
    "WPA3_TRANSITION_ENTERPRISE": 10,
}


def logger():
    return get_logger(__name__)


def wifi_dut_marker(
    ext_custom_bit=0,
    tcp_feat_bit=0,
    ext_tcp_feat_bit=0,
    ca_cert=None,
    eap_cert=None,
    wifi_stack_len=3584,
    ble_stack_len=3584,
    oper_mode=0,
):
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.TCPIPBypass
        | tcp_feat_bit,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if eap_cert:
        config["eap_cert"] = eap_cert
    return pytest.mark.config("wifi_dut", wifi=config)


class MQTTConnectionThread(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        wifi_access_point=None,
        wifi_sniffer=None,
        topic=None,
        dut_addr=None,
        request=None,
        mqtt_server=None,
        mqtt_client=None,
        message=None,
        sl_collections=None,
        client_id=None,
        qos=None,
        profile=None,
        dut_mac_address=None,
        sniffer_filter=None,
        enable_tls=False,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.topic = topic
        self.dut_addr = dut_addr
        self.request = request
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.message = message
        self.sl_collections = sl_collections
        self.client_id = client_id
        self.qos = qos
        self.profile = profile
        self.dut_mac_address = dut_mac_address
        self.sniffer_filter = sniffer_filter
        self.enable_tls = enable_tls

    def run(self):
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.request.node.name}.pcap"
        )
        self.wifi_dut.interfaces.wifi.sl_net_set_profile(
            ssid=self.profile["ssid"],
            security=Map_security[self.profile["security"]],
            credential_id=(1 if Map_security[self.profile["security"]] != 0 else 0),
            priority=1,
            profile_id=0,
            channel=self.profile["channel"],
            encryption=self.profile["encryption_type"],
        )
        self.wifi_dut.interfaces.wifi.sl_net_set_credential(
            credential=self.profile["passphrase"], cred_id=1
        )
        self.wifi_dut.interfaces.wifi.sl_net_up(mode="client")
        device_ip = self.wifi_dut.interfaces.wifi.display_device_ip_lwip()
        self.wifi_dut.interfaces.wifi.set_performance_profile(
            mode="power_save_low_latency"
        )
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        # self.dut_addr['device_ip'] = self.wifi_dut.interfaces.wifi.get_device_ip(device_ip=device_ip)
        # self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        # self.dut_addr['dut_mac_address'] = self.dut_mac_address
        # logger().info(f"\n DUT INFO: {self.dut_addr} \n")

    def mqtt_connect(self):
        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.mqtt.lwip_mqtt_connect(
            server=self.mqtt_server.interfaces.mqtt,
            enable_ssl=1 if self.enable_tls else 0,
            dut_port=5001,
            broker_port=8883 if self.enable_tls else 1883,
        )
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        time.sleep(5)

    def subscribe_and_publish(self, qos):
        self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(
            topic=self.topic, qos=self.qos
        )
        self.wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(
            topic=self.topic, qos=self.qos
        )
        self.wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
            topic=self.topic, message=self.message, qos=self.qos, timeout=20
        )

    def validate_mqtt_messages(self):
        logger().info(f"\n Validating MQTT Messages on DUT \n")
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert (
            msgs[0].topic == self.topic
        ), "No message received by mqtt-client on subscribed topic"
        assert (
            msgs[0].qos == self.qos
        ), "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == self.message, (
            "No message is received by mqtt-client on subscribed topic or "
            "message received is wrong"
        )
        logger().info(f"\n Validating MQTT Messages on DUT \n")
        yield_data = self.wifi_dut.interfaces.mqtt.lwip_mqtt_yield()
        pattern = re.compile(
            r"Topic:\s*(?P<Topic>[^\r\n]+)\s*Message:\s*(?P<Message>[^\r\n]+)",
            re.DOTALL,
        )

        match = pattern.search(yield_data)
        if match:
            topic = match.group("Topic")
            message = match.group("Message")
            logger().info(
                f"Received MQTT message on DUT - Topic: {topic}, Message: {message}"
            )
        else:
            raise AssertionError("No MQTT message received on DUT")

    def verify_ps_validation(self):
        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_addr["dut_mac_address"], filter_name="ps_poll"
            )
        )
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"]
        assert snif_pkt_count, "\n PS-POLL Packets are not captured in the Sniffer \n"


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "mqtt_disconnect",
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
def test_mqtt_subscribe_publish_with_qos0_on_host_lwip_C876776(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    mqtt_server,
    mqtt_client,
    sniffer_filter,
    sl_collections,
    request,
):
    topic = "Topic_C876776"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS0
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    try:
        mqtt_thread = MQTTConnectionThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            topic=topic,
            request=request,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            message=message,
            sl_collections=sl_collections,
            client_id=client_id,
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=False,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "mqtt_disconnect",
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
def test_mqtts_subscribe_publish_with_qos0_on_host_lwip_C876777(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    mqtt_server,
    mqtt_client,
    sniffer_filter,
    sl_collections,
    request,
):
    topic = "Topic_C876776"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS0
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    try:
        mqtt_thread = MQTTConnectionThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            topic=topic,
            request=request,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            message=message,
            sl_collections=sl_collections,
            client_id=client_id,
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=True,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "mqtt_disconnect",
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
def test_mqtt_subscribe_publish_with_qos0_on_host_lwip_C876776(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    mqtt_server,
    mqtt_client,
    sniffer_filter,
    sl_collections,
    request,
):
    topic = "Topic_C876776"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS0
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    try:
        mqtt_thread = MQTTConnectionThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            topic=topic,
            request=request,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            message=message,
            sl_collections=sl_collections,
            client_id=client_id,
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=False,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "mqtt_disconnect",
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
def test_mqtts_subscribe_publish_with_qos0_on_host_lwip_C876777(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    mqtt_server,
    mqtt_client,
    sniffer_filter,
    sl_collections,
    request,
):
    topic = "Topic_C876776"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS0
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    try:
        mqtt_thread = MQTTConnectionThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            topic=topic,
            request=request,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            message=message,
            sl_collections=sl_collections,
            client_id=client_id,
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=True,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "mqtt_disconnect",
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
def test_mqtt_subscribe_publish_with_qos1_on_host_lwip_C876778(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    mqtt_server,
    mqtt_client,
    sniffer_filter,
    sl_collections,
    request,
):
    topic = "Topic_C876776"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS1
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    try:
        mqtt_thread = MQTTConnectionThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            topic=topic,
            request=request,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            message=message,
            sl_collections=sl_collections,
            client_id=client_id,
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=False,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "mqtt_disconnect",
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
def test_mqtts_subscribe_publish_with_qos1_on_host_lwip_C876779(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    mqtt_server,
    mqtt_client,
    sniffer_filter,
    sl_collections,
    request,
):
    topic = "Topic_C876776"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS1
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    try:
        mqtt_thread = MQTTConnectionThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            topic=topic,
            request=request,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            message=message,
            sl_collections=sl_collections,
            client_id=client_id,
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=True,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "mqtt_disconnect",
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
def test_mqtt_subscribe_publish_with_qos2_on_host_lwip_C876780(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    mqtt_server,
    mqtt_client,
    sniffer_filter,
    sl_collections,
    request,
):
    topic = "Topic_C876776"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    try:
        mqtt_thread = MQTTConnectionThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            topic=topic,
            request=request,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            message=message,
            sl_collections=sl_collections,
            client_id=client_id,
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=False,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "mqtt_disconnect",
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
def test_mqtts_subscribe_publish_with_qos2_on_host_lwip_C876781(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    mqtt_server,
    mqtt_client,
    sniffer_filter,
    sl_collections,
    request,
):
    topic = "Topic_C876776"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    try:
        mqtt_thread = MQTTConnectionThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            topic=topic,
            request=request,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            message=message,
            sl_collections=sl_collections,
            client_id=client_id,
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=True,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
