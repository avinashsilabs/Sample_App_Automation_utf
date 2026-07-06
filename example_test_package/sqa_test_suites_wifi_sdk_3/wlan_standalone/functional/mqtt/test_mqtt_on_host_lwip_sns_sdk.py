import time
import pytest
import string
import re
import random
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xMqttQos,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils import get_tls_certificate_dir

"""
Author: Achal Raghav

Description:
This file contains Pytest test cases and helper threads for validating MQTT functionality
on the Wi-Fi SDK when running on host LWIP. The tests cover MQTT and MQTT-over-TLS
connections, subscribe/publish flows, disconnect/reconnect cycles, and validations using
a Wi-Fi sniffer (e.g., TLS handshake visibility, TCP flag checks, keep-alive behavior,
and power-save PS-POLL frames).

Test Cases Overview:
\- C876788: MQTTS subscribe/publish/disconnect loop with sniffer validation (power_save)
\- C876789: MQTTS subscribe/publish/disconnect loop with Wi\-Fi leave/join between cycles
\- C876790: MQTTS subscribe/publish/disconnect with `sl_net_down` and `sl_net_deinit` cycles 
\- C876807: MQTTS subscribe/publish every 30 min with long duration 

Key Components:
\- `MQTTConnectionThread`: Joins AP, brings up LWIP IP, configures performance/power\-save,
  connects to broker, runs subscribe/publish, validates received messages, and performs
  sniffer\-based checks\.
\- `ParallelThread` / `MQTTClientThread`: Publish loops used for concurrency and message
  validation on DUT/client\.

Requirements:
\- Python 3\.x
\- Pytest framework
\- UTF test framework and dependencies
\- Wi\-Fi DUT supporting LWIP MQTT and MQTTS \(SSL/TLS\)
\- MQTT broker \(plain and TLS\) and an MQTT client endpoint
\- Access point and Wi\-Fi sniffer setup \(tshark/pcap capture support\)
"""

def logger():
    return get_logger(__name__)


def _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=None):
    """Release DUT TLS cert heap and recover from bad async state after a test."""
    if mqtt_thread is not None:
        mqtt_thread.free_certificate_allocations()
    if wifi_dut.interfaces.wifi.is_dut_bad_state:
        wifi_dut.interfaces.wifi.deinit_test_agent_threads()


# TLS SNI hostname for the DUT mbedTLS client (broker cert SAN: example.com).
MQTT_TLS_HOSTNAME = "example.com"


def wifi_dut_marker(
    tcp_feat_bit=0,
    wifi_stack_len=4096,
    thread_count=1,
    ca_cert=None,
    eap_cert=None,
    coex_mode=None,
    memory_mode=None,
):
    if coex_mode is None:
        coex_mode = Si91xCoexMode.WLANOnly
    if memory_mode is None:
        memory_mode = Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode
    config = {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": coex_mode,
        "features": Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.TCPIPBypass
        | tcp_feat_bit,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | memory_mode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": thread_count, "stack_len": wifi_stack_len}},
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
        request=None,
        mqtt_server=None,
        mqtt_client=None,
        message=None,
        qos=None,
        profile=None,
        sniffer_filter=None,
        enable_tls=False,
        keepalive_time=0,
        retain=0,
        ca_cert="ca-cert.pem",
        server_cert="server-cert.pem",
        server_key="server-key.pem",
        client_id="Si91x_mqtt_client",
        enable_bt_powersave=True,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.topic = topic
        self.dut_addr = {}
        self.request = request
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.message = message
        self.qos = qos
        self.profile = profile
        self.sniffer_filter = sniffer_filter
        self.enable_tls = enable_tls
        self.keepalive_time = keepalive_time
        self.retain = retain
        self.ca_cert = ca_cert
        self.server_cert = server_cert
        self.server_key = server_key
        self.client_id = client_id
        self.enable_bt_powersave = enable_bt_powersave
        self._mqtt_is_clean_session = 1
        self._mqtt_enable_will = 0
        self._mqtt_retain_will = 0
        self._mqtt_will_topic = None
        self._mqtt_will_message = None
        self._cert_alloc_addresses = []

    def free_certificate_allocations(self):
        if not self._cert_alloc_addresses:
            return
        if self.enable_tls:
            try:
                self.wifi_dut.interfaces.mqtt.lwip_mqtt_disconnect()
            except Exception as ex:
                logger().warning(
                    f"MQTT disconnect before cert memory cleanup skipped: {ex}"
                )
        for address in self._cert_alloc_addresses:
            try:
                self.wifi_dut.interfaces.wifi.memory_free(address)
            except Exception as ex:
                logger().warning(
                    f"Certificate memory cleanup failed for {address}: {ex}"
                )
        self._cert_alloc_addresses.clear()

    def load_certificate(self, certificate):
        cert_file = str(get_tls_certificate_dir().joinpath(certificate))
        with open(cert_file) as f:
            cert_contents = f.read()
        size = len(cert_contents)
        logger().info(f"\nLoading  Certificate {certificate} ")
        buffer_size = (512 * (int(size / 512))) + 512
        address = self.wifi_dut.interfaces.wifi.allocate_memory(size=buffer_size)
        self.wifi_dut.interfaces.wifi.load_memory(
            address, size=size, write_content=cert_contents
        )
        self._cert_alloc_addresses.append(address)
        return address, size

    def run(self):
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.request.node.name}.pcap"
        )
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.profile["ssid"],
            passphrase=self.profile["passphrase"],
            security=self.profile["security"].lower(),
            channel=self.profile["channel"],
            enable_lwip=1,
        )
        self.wifi_dut.interfaces.wifi.start_ip_lwip()
        attempt = 3
        flag = False
        while attempt > 0:
            try:
                self.wifi_dut.interfaces.wifi.sl_net_up(mode="client")
                flag = True
            except Exception as e:
                attempt -= 1
                logger().info(
                    f"sl_net_up failed with exception {e}, retrying...{attempt} attempts left"
                )
            if flag:
                break
        device_ip = self.wifi_dut.interfaces.wifi.display_device_ip_lwip()
        self.wifi_dut.interfaces.wifi.set_performance_profile(
            mode="power_save_low_latency"
        )
        if self.enable_bt_powersave:
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
            )
        self.dut_addr["device_ip"] = self.wifi_dut.interfaces.wifi.get_device_ip(
            device_ip=device_ip
        )
        self.dut_addr["dut_mac_address"] = (
            self.wifi_dut.interfaces.wifi.get_mac_address()
        )
        logger().info(f"\n DUT INFO: {self.dut_addr} \n")

    def mqtt_connect(self, expected_status=SLStatus.SL_STATUS_OK, configure_tls_certs=True):
        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        broker = self.mqtt_server.interfaces.mqtt.hostname_or_ip_address
        if self.enable_tls and configure_tls_certs:
            self.free_certificate_allocations()
            ca_cert_address, ca_cert_size = self.load_certificate(certificate=self.ca_cert)
            server_cert_address, server_cert_size = self.load_certificate(
                certificate=self.server_cert
            )
            server_key_address, server_key_size = self.load_certificate(
                certificate=self.server_key
            )
            self.wifi_dut.interfaces.wifi.lwip_mqtt_configure(
                will_topic=self._mqtt_will_topic,
                will_message=self._mqtt_will_message,
                enable_will=self._mqtt_enable_will,
                retain_will=self._mqtt_retain_will,
                is_clean_session=self._mqtt_is_clean_session,
                ca_cert=ca_cert_address,
                client_cert=server_cert_address,
                client_key=server_key_address,
                ca_cert_size=ca_cert_size,
                client_cert_size=server_cert_size,
                client_key_size=server_key_size,
            )
        self.wifi_dut.interfaces.mqtt.lwip_mqtt_connect(
            server=self.mqtt_server.interfaces.mqtt,
            mqtt_server=broker,
            enable_ssl=1 if self.enable_tls else 0,
            dut_port=5001,
            broker_port=8883 if self.enable_tls else 1883,
            connection_timeout_ms=20000 if self.enable_tls else None,
            keep_alive_interval_ms=self.keepalive_time,
            client_id=self.client_id,
            tls_hostname=MQTT_TLS_HOSTNAME if self.enable_tls else None,
            expected_status=expected_status,
        )
        self.mqtt_client.interfaces.mqtt.disable_certificate_verification = True
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        time.sleep(5)

    def subscribe_and_publish(self, qos, higer_data_length=0):
        self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(
            topic=self.topic, qos=self.qos
        )
        self.wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(
            topic=self.topic, qos=self.qos
        )
        self.wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
            topic=self.topic,
            message=self.message,
            qos=self.qos,
            timeout=20,
            retain=self.retain,
            higher_data_len=higer_data_length,
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
        logger().info(
            f" Received MQTT message on MQTT Client - Topic: {msgs[0].topic}, Message: {msgs[0].payload.decode()}, QOS: {msgs[0].qos} "
        )
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
        self.mqtt_client.interfaces.mqtt.received_messages.clear()
        yield_data = self.wifi_dut.interfaces.mqtt.lwip_mqtt_yield(
            yield_timeout_ms=2000
        )
        pattern = re.compile(
            r"Topic:\s*(?P<Topic>[^,]+),\s*Message:\s*(?P<Message>[^\r\n]+)",
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







@wifi_dut_marker(
    tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
    coex_mode=Si91xCoexMode.WLANOnly,
    memory_mode=Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "lwip_mqtt_disconnect",
        "unassociated",
        "disable_external_stack"
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
@pytest.mark.test_src_map_id('C876788')
def test_mqtts_subscribe_publish_disconnect_for_30min_C876788(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    mqtt_server,
    mqtt_client,
    sniffer_filter,
    sl_collections,
    request,
    utf_constants,
):
    time_duration = utf_constants.get("time_duration")
    topic = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=1200))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    mqtt_thread = None
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
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=True,
            enable_bt_powersave=True,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        sw = Stopwatch()
        while sw.elapsed_sec < time_duration:
            mqtt_thread.mqtt_connect()
            mqtt_thread.subscribe_and_publish(qos=qos, higer_data_length=1)
            mqtt_thread.validate_mqtt_messages()
            wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
            wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


@wifi_dut_marker(
    tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
    coex_mode=Si91xCoexMode.WLANOnly,
    memory_mode=Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "lwip_mqtt_disconnect",
        "unassociated",
        "disable_external_stack"
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
@pytest.mark.test_src_map_id('C876789')
def test_mqtts_subscribe_publish_disconnect_over_wifi_for_30min_C876789(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    mqtt_server,
    mqtt_client,
    sniffer_filter,
    sl_collections,
    request,
    utf_constants,
):
    time_duration = utf_constants.get("time_duration")
    topic = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=1200))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    mqtt_thread = None
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
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=True,
            enable_bt_powersave=True,
        )
        sw = Stopwatch()
        while sw.elapsed_sec < time_duration:
            mqtt_thread.start()
            mqtt_thread.wait_for_exit()
            mqtt_thread.mqtt_connect()
            mqtt_thread.subscribe_and_publish(qos=qos, higer_data_length=1)
            mqtt_thread.validate_mqtt_messages()
            wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
            wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
            wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


@pytest.mark.skip(reason="Flaky test case - PR #3036 created to fix this")
@wifi_dut_marker(
    tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
    coex_mode=Si91xCoexMode.WLANOnly,
    memory_mode=Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "lwip_mqtt_disconnect",
        # "wifi_powersave_disable",
        # "bt_powersave_disable",
        "unassociated",
        "disable_external_stack"
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
@pytest.mark.test_src_map_id('C876790')
def test_mqtts_subscribe_publish_disconnect_deinit_for_30min_C876790(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    mqtt_server,
    mqtt_client,
    sniffer_filter,
    sl_collections,
    request,
    utf_constants,
):
    time_duration = utf_constants.get("time_duration")
    topic = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=1200))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    mqtt_thread = None
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
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=True,
            enable_bt_powersave=True,
        )
        sw = Stopwatch()
        while sw.elapsed_sec < time_duration:
            if not wifi_dut.interfaces.wifi.inited:
                wifi_dut.interfaces.wifi.init(mode="client", config_required=True)
            mqtt_thread.start()
            mqtt_thread.wait_for_exit()
            mqtt_thread.mqtt_connect()
            mqtt_thread.subscribe_and_publish(qos=qos)
            mqtt_thread.validate_mqtt_messages()
            wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
            wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
            wifi_dut.interfaces.wifi.sl_net_down(mode="client")
            wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


@wifi_dut_marker(
    tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
    coex_mode=Si91xCoexMode.WLANOnly,
    memory_mode=Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "lwip_mqtt_disconnect",
        "unassociated",
        "disable_external_stack"
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
@pytest.mark.test_src_map_id('C876807')
def test_mqtts_subscribe_publish_every_30_min_C876807(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    mqtt_server,
    mqtt_client,
    sniffer_filter,
    sl_collections,
    request,
    utf_constants,
):
    time_duration = utf_constants.get("time_duration")
    topic = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=1200))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    mqtt_thread = None
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
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=True,
            enable_bt_powersave=True,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=qos)
        wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=topic, qos=qos)
        sw = Stopwatch()
        while sw.elapsed_sec < (time_duration + 120):
            wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
                topic=topic,
                message=message,
                qos=qos,
                timeout=20,
                higher_data_len=1,
            )
            mqtt_thread.validate_mqtt_messages()
            time.sleep(1800)
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)
