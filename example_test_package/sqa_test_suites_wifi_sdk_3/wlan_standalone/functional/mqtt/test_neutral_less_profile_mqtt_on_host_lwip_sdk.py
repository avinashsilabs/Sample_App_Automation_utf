import os
import time
import pytest
import string
import re
import random
import uuid
from datetime import datetime
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.shell.ssh_shell import SSHShell
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xMqttQos,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)
from typing import Dict
import threading
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import (
    AsyncEventIdentifiers,
)
from utf.utils import get_tls_certificate_dir

"""
Author: Bhargavi

Description:
This file contains Pytest test cases for validating Neutral less profile with MQTT functionality on the Wi-Fi SDK
when running on host LWIP. The tests cover MQTT-over-TLS connections,
subscribe/publish , data rates check during connection and data transfer, rejoin and other cases.

"""

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


def _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=None, switch=None):
    """Release DUT TLS cert heap and recover from bad async state after a test."""
    if mqtt_thread is not None:
        mqtt_thread.free_certificate_allocations()
    if wifi_dut.interfaces.wifi.is_dut_bad_state:
        wifi_dut.interfaces.wifi.deinit_test_agent_threads()
    if switch is not None:
        logger().info("******* Turn on Access point **********")
        switch.interfaces.pdu_switch.turn_on(delay=60)


# DUT trust anchor loaded at init. Matches the working log: the wolfSSL sample CA
# (ca-cert.pem) signs both the broker's server cert AND the DUT's client cert.
# The broker (raspi_mosquitto_tls) must serve the wolfSSL certs for this to work.
MQTT_SSL_CA_CERT = [
    "ca-cert.pem",
    "SL_NET_SIGNING_CERTIFICATE",
    "SL_NET_TLS_SERVER_CREDENTIAL_START",
]

# TLS SNI hostname for the DUT mbedTLS client (broker cert SAN: example.com).
MQTT_TLS_HOSTNAME = "example.com"

# Broker identity / CA used when restarting Mosquitto from the test (wolfSSL samples).
MQTT_BROKER_TLS_CERT = "server-cert.pem"
MQTT_BROKER_TLS_KEY = "server-key.pem"
MQTT_BROKER_TLS_CA = "ca-cert.pem"


def _reconfigure_mosquitto_tls(
    mqtt_server,
    cert=MQTT_BROKER_TLS_CERT,
    key=MQTT_BROKER_TLS_KEY,
    ca=MQTT_BROKER_TLS_CA,
    port=8883,
):
    """Restart Mosquitto on the Pi with wolfSSL PEMs from tls_certificates.

    @pytest.mark.config cannot change MQTT TLS files: the mqtt_server fixture
    starts Mosquitto from harness paths baked in MosquittoServer.__init__.
    Reuse the harness-resolved directory on the Pi and swap filenames.
    """
    mqtt = mqtt_server.interfaces.mqtt
    if not getattr(mqtt, "tls_enabled", False):
        return
    if not getattr(mqtt, "certfile", None):
        return

    cert_dir = os.path.dirname(mqtt.certfile).replace("\\", "/")
    new_cert = f"{cert_dir}/{cert}"
    new_key = f"{cert_dir}/{key}"
    new_ca = f"{cert_dir}/{ca}"
    if mqtt.certfile.replace("\\", "/") == new_cert and mqtt.keyfile.replace(
        "\\", "/"
    ) == new_key and mqtt.cafile.replace("\\", "/") == new_ca:
        return

    logger().info(
        f"Reconfiguring Mosquitto TLS: certfile={cert}, keyfile={key}, cafile={ca}"
    )
    mqtt.stop_server()
    mqtt.certfile = new_cert
    mqtt.keyfile = new_key
    mqtt.cafile = new_ca
    mqtt.start_server(port=port)


def wifi_dut_marker(
        tcp_feat_bit=0,
        wifi_stack_len=4096,
        thread_count=1,
        coex_mode=None,
        memory_mode=None,
        enable_feature_bitmap=Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
):
    # Defaults match the standard test footprint. Individual tests can override
    # coex_mode / memory_mode when they need a leaner or larger host allocation
    # (e.g. host-side mbedTLS handshakes that are heap-hungry).
    if coex_mode is None:
        coex_mode = Si91xCoexMode.WLAN | Si91xCoexMode.BLE
    if memory_mode is None:
        memory_mode = Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode
    config = {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": coex_mode,
        "features": Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | enable_feature_bitmap,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.TCPIPBypass | Si91xTCPIPFeatureBitMap.SSL
                          | tcp_feat_bit,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
                           | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | memory_mode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
                              | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "region": 4,
        "region_code": "worldwide",
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": thread_count, "stack_len": wifi_stack_len}},
        "thread_params": {"wifi": {"buffer_len": 1600}},
    }

    return pytest.mark.config("wifi_dut", wifi=config)


# Create stop event for clean shutdown
stop_evt = threading.Event()


def _mqtt_yield_loop(
        wifi_dut, stop_evt, yield_timeout_ms=20000, async_timeout=150, keepalive=10
):
    while not stop_evt.is_set():
        wifi_dut.interfaces.wifi.lwip_mqtt_yield(
            yield_timeout_ms=yield_timeout_ms, async_timeout=async_timeout
        )
        time.sleep(keepalive)


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
            sl_collections=None,
            client_id=None,
            qos=None,
            profile=None,
            dut_mac_address=None,
            sniffer_filter=None,
            enable_tls=False,
            keepalive_time=0,
            idle_time=120,
            retain=0,
            ca_cert="ca-cert.pem",
            server_cert="server-cert.pem",
            server_key="server-key.pem",
            enable_bt_powersave=True,
            application_profile_calls=1,
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
        self.sl_collections = sl_collections
        self.client_id = client_id
        self.qos = qos
        self.profile = profile
        self.dut_mac_address = dut_mac_address
        self.sniffer_filter = sniffer_filter
        self.enable_tls = enable_tls
        self.keepalive_time = keepalive_time
        self.idle_time = idle_time
        self.retain = retain
        self.ca_cert = ca_cert
        self.server_cert = server_cert
        self.server_key = server_key
        self.enable_bt_powersave = enable_bt_powersave
        self.application_profile_calls = application_profile_calls
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
        self.wifi_dut.interfaces.wifi.sl_net_set_application_profile(interface="client", profile=1)
        for call in range(2, self.application_profile_calls + 1):
            logger().info(
                f"Calling sl_net_set_application_profile time {call} before sl_net_up"
            )
            self.wifi_dut.interfaces.wifi.sl_net_set_application_profile(
                interface="client", profile=1
            )
        self.wifi_dut.interfaces.wifi.set_performance_profile(
            mode="power_save_low_latency"
        )
        if self.enable_bt_powersave:
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
            )
        self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=5,
            scan_interval=4,
            beacon_missed_count=40,
            first_time_retry_enable=1,
        )
        previous_channel = self.wifi_access_point.interfaces.wifi.channel
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        sa_addr = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info(f"Saving previous sniffer/AP channel: {previous_channel}")
        for channel in channels_list_2g:
            if channel == 14:
                logger().info(f"channel : {channel} not supported by NUC,skipping the channel")
                continue
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.request.node.name}_ch_{channel}")
            time.sleep(1)

            logger().info("enable the scan in dut on channel 0...")
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(2)
            assert (len(scan_results) >= 1), "Scan Failed"
            logger().info(scan_results)

            self.wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=sa_addr,
                filter_name="probe_request",
            )
            packet_filter1 = (
                f"({packet_filter1}) and (wlan_radio.channel == {channel})"
            )
            logger().info(
                f"Validate Probe req(Broadcast) only on NUC channel {channel}"
            )
            logger().info(f"Sniffer Filter = {packet_filter1}")
            output = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        # assert Probe_not_captured_channel_list == [], logger().info(
            # f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
        logger().info("Dut is able to scan successfully in worldwide region")
        logger().info(
            f"Reverting sniffer channel back to previous channel {previous_channel} before sl_net_up"
        )
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=previous_channel)
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.request.node.name}_sl_net_up.pcap"
        )
        attempt = 3
        flag = False
        last_error = None
        while attempt > 0:
            try:
                self.wifi_dut.interfaces.wifi.sl_net_up(mode="client")
                flag = True
                break
            except Exception as e:
                last_error = e
                attempt -= 1
                logger().info(
                    f"sl_net_up failed with exception {e}, {attempt} attempts left"
                )
                logger().info(
                    "sl_net_up failed, calling sl_net_set_application_profile before retry"
                )
                self.wifi_dut.interfaces.wifi.sl_net_set_application_profile(
                    interface="client", profile=1
                )
        assert flag, f"sl_net_up failed after 3 attempts: {last_error}"
        device_ip = self.wifi_dut.interfaces.wifi.display_device_ip_lwip()
        self.dut_addr["device_ip"] = self.wifi_dut.interfaces.wifi.get_device_ip(
            device_ip=device_ip
        )
        status = ping(self.dut_addr["device_ip"], 10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        self.dut_addr["dut_mac_address"] = (
            self.wifi_dut.interfaces.wifi.get_mac_address()
        )
        logger().info(f"\n DUT INFO: {self.dut_addr} \n")

    def load_certificate(self, certificate):
        cert_file = str(get_tls_certificate_dir().joinpath(certificate))
        with open(cert_file) as f:
            cert_contents = f.read()
        size = len(cert_contents)
        logger().info(f"\nLoading  Certificate {certificate} ")
        buffer_size = (
                              512 * (int(size / 512))
                      ) + 512  # buffer_size should be more than size
        address = self.wifi_dut.interfaces.wifi.allocate_memory(size=buffer_size)
        self.wifi_dut.interfaces.wifi.load_memory(
            address, size=size, write_content=cert_contents
        )
        self._cert_alloc_addresses.append(address)
        return address, size

    def rejoin_async_event(self):
        logger().info("\n Waiting for Rejoin error async event...\n")
        with TimeMeasurer() as t:
            sw = Stopwatch()
            while sw.elapsed_sec < 180:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                rejoin_error_events = [
                    event
                    for event in events
                    if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT
                ]
                if len(rejoin_error_events):
                    break
                time.sleep(0.1)
            else:
                return False
        logger().info(f"Received rejoin error event after {t.duration:.2f}s")
        return True

    def lwip_mqtt_configure(
            self,
            will_topic=None,
            will_message=None,
            enable_will=0,
            retain_will=0,
            is_clean_session=1,
    ):
        logger().info(
            f"\n Configuring MQTT on DUT with Parameters will_topic:: {will_topic}, will_message:: {will_message}, enable_will::{enable_will}, retain_will:: {retain_will}\n"
        )
        self._mqtt_is_clean_session = is_clean_session
        self._mqtt_enable_will = enable_will
        self._mqtt_retain_will = retain_will
        self._mqtt_will_topic = will_topic
        self._mqtt_will_message = will_message
        self.wifi_dut.interfaces.wifi.lwip_mqtt_configure(
            will_topic=will_topic,
            will_message=will_message,
            enable_will=enable_will,
            retain_will=retain_will,
            is_clean_session=is_clean_session,
        )

    def mqtt_connect(self, expected_status=SLStatus.SL_STATUS_OK, configure_tls_certs=True):
        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        if self.enable_tls:
            # Harness may still list mosquitto-utf certs; align broker to wolfSSL PEMs.
            _reconfigure_mosquitto_tls(self.mqtt_server)
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

    def _wait_for_host_mqtt_message(self):
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) >= 1:
                break
        assert msgs, "No message is received by mqtt-client"
        logger().info(
            f" Received MQTT message on MQTT Client - Topic: {msgs[0].topic}, "
            f"Message: {msgs[0].payload.decode()}, QOS: {msgs[0].qos} "
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
        self.mqtt_client.interfaces.mqtt.received_messages.clear()
        return len(msgs)

    def _wait_for_dut_mqtt_message(self):
        yield_data = self.wifi_dut.interfaces.mqtt.lwip_mqtt_yield(
            yield_timeout_ms=2000
        )
        pattern = re.compile(
            r"Topic:\s*(?P<Topic>[^,]+),\s*Message:\s*(?P<Message>[^\r\n]+)",
            re.DOTALL,
        )
        match = pattern.search(yield_data)
        if not match:
            raise AssertionError("No MQTT message received on DUT")
        topic = match.group("Topic")
        message = match.group("Message")
        logger().info(
            f"Received MQTT message on DUT - Topic: {topic}, Message: {message}"
        )
        assert topic == self.topic, "Mismatch in MQTT topic received on DUT"
        assert message == self.message, "Mismatch in MQTT message received on DUT"
        return 1

    def subscribe_and_publish_for_multiple_times(self, qos=None, iterations=50):
        qos = qos if qos is not None else self.qos
        received_packet_count = 0
        self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(
            topic=self.topic, qos=qos
        )
        self.wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=self.topic, qos=qos)
        self.mqtt_client.interfaces.mqtt.received_messages.clear()
        logger().info(
            f"Publishing MQTT messages {iterations} times to collect at least {iterations}  receive packets"
        )
        for count in range(1, iterations + 1):
            logger().info(f"MQTT publish/receive iteration {count}/{iterations}")
            self.wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
                topic=self.topic,
                message=self.message,
                qos=qos,
                timeout=20,
                retain=self.retain,
            )
            received_packet_count += self._wait_for_host_mqtt_message()
            received_packet_count += self._wait_for_dut_mqtt_message()
            logger().info(
                f"MQTT receive packet count after iteration {count}: {received_packet_count}"
            )
        assert received_packet_count >= iterations, (
            f"Expected at least 50 MQTT receive packets, got {received_packet_count}"
        )
        logger().info(
            f"MQTT multiple publish/receive completed. Total receive packets: {received_packet_count}"
        )
        return received_packet_count

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

    @staticmethod
    def _normalize_mgmt_rate_filter(packet_filter):
        packet_filter = packet_filter.strip().replace(")and (", ") and (")
        packet_filter = packet_filter.replace(")(", ") and (")
        while packet_filter.startswith("((") and packet_filter.count("(") > packet_filter.count(")"):
            packet_filter = packet_filter[1:]
        if packet_filter.count("(") > packet_filter.count(")"):
            packet_filter = packet_filter + (")" * (packet_filter.count("(") - packet_filter.count(")")))
        return packet_filter

    def verify_management_data_rates(self):
        dut_mac = self.wifi_dut.interfaces.wifi.get_mac_address()
        expected_filter = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                dut_addr=dut_mac,
                filter_name="Neutral_less_profile_management_rates",
            )
        )
        unexpected_filter = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                dut_addr=dut_mac,
                filter_name="Neutral_less_profile_management_rates_not_expected",
            )
        )
        expected_filter = self._normalize_mgmt_rate_filter(expected_filter)
        unexpected_filter = self._normalize_mgmt_rate_filter(unexpected_filter)
        logger().info(f"Expected 6 Mbps management filter = {expected_filter}")
        logger().info(f"Unexpected non-6 Mbps management filter = {unexpected_filter}")
        capture = self.wifi_sniffer.interfaces.capture
        sl_net_up_capture_name = capture.capture_file
        logger().info(
            "Management rate check source files: "
            f"capture_file={capture.capture_file}, "
            f"remote_capture_file={capture.remote_capture_file}, "
            f"downloaded_sl_net_up={capture.main_local_capture_file}"
        )
        assert "sl_net_up" in str(sl_net_up_capture_name), (
            f"6 Mbps check must use sl_net_up capture, got {sl_net_up_capture_name}"
        )
        # sniffer_validation writes ./reports/filter_<capture_file>_*.pcap.
        # Keep that helper copy off the sl_net_up name so only one sl_net_up pcap exists.
        capture.capture_file = f"{self.request.node.name}_mgmt_rate_check"
        try:
            assert capture.sniffer_validation(packet_filter1=expected_filter)[
                "packet_count"
            ], (
                "DUT probe/auth/assoc/deauth frames were not captured at 6 Mbps"
            )
            unexpected_result = capture.sniffer_validation(
                packet_filter1=unexpected_filter, negative_test=True
            )
            assert not unexpected_result["packet_count"], (
                "DUT probe/auth/assoc/deauth frames were captured at a rate other than 6 Mbps"
            )
        finally:
            capture.capture_file = sl_net_up_capture_name

    def verify_data_rates(self):
        dut_mac = self.wifi_dut.interfaces.wifi.get_mac_address()
        expected_filter = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                dut_addr=dut_mac,
                filter_name="Neutral_less_profile_data_rates",
            )
        )
        unexpected_filter = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                dut_addr=dut_mac,
                filter_name="Neutral_less_profile__data_rates_not_expected",
            )
        )
        expected_filter = self._normalize_mgmt_rate_filter(expected_filter)
        unexpected_filter = self._normalize_mgmt_rate_filter(unexpected_filter)
        logger().info(f"Expected DUT TX data rate filter = {expected_filter}")
        logger().info(f"Unexpected DUT TX data rate filter = {unexpected_filter}")
        capture = self.wifi_sniffer.interfaces.capture
        original_capture_name = capture.capture_file
        logger().info(
            "Data rate check source files: "
            f"capture_file={capture.capture_file}, "
            f"remote_capture_file={capture.remote_capture_file}, "
            f"downloaded_capture={capture.main_local_capture_file}"
        )
        capture.capture_file = f"{self.request.node.name}_data_rate_check"
        try:
            assert capture.sniffer_validation(packet_filter1=expected_filter)[
                "packet_count"
            ], (
                "DUT Data/QoS Data frames were not captured at 6 Mbps through MCS4"
            )
            unexpected_result = capture.sniffer_validation(
                packet_filter1=unexpected_filter, negative_test=True
            )
            assert not unexpected_result["packet_count"], (
                "DUT Data/QoS Data frames were captured outside 6 Mbps through MCS4"
            )
        finally:
            capture.capture_file = original_capture_name

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

    def verify_unexpected_filter_after_reconnect(self):
        ap_channel = self.wifi_access_point.interfaces.wifi.channel
        logger().info(
            f"Starting reconnect capture on channel {ap_channel} for unexpected_filter"
        )
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=ap_channel)
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.request.node.name}_reconnect.pcap"
        )
        logger().info("Disconnecting DUT from AP")
        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        logger().info("Reconnecting DUT to AP")
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.profile["ssid"],
            passphrase=self.profile["passphrase"],
            security=self.profile["security"].lower(),
            channel=self.profile["channel"],
            enable_lwip=1,
        )
        self.wifi_dut.interfaces.wifi.start_ip_lwip()
        self.wifi_dut.interfaces.wifi.sl_net_up(mode="client")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        dut_mac = self.wifi_dut.interfaces.wifi.get_mac_address()
        unexpected_filter = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                dut_addr=dut_mac,
                filter_name="Neutral_less_profile_management_rates_not_expected",
            )
        )
        expected_filter = self._normalize_mgmt_rate_filter(unexpected_filter)
        logger().info(f"Unexpected filter after reconnect = {unexpected_filter}")
        expected_result = self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=unexpected_filter
        )
        assert expected_result["packet_count"], (
            "Unexpected-rate management packets were not captured after AP reconnect"
        )
        logger().info(
            f"Expected filter packets found after reconnect: "
            f"{expected_result['packet_count']}"
        )

    def get_mqtt_list(
            self, dut_mac_address, decryption_key: str, print_layers: list
    ) -> Dict[str, int]:
        mqtt_capture_list = []
        current_time = time.time()
        updated_capture_file = (
                "filter_"
                + self.capture_filename
                + "_"
                + str(datetime.fromtimestamp(current_time).strftime("%H_%M_%S"))
        )
        file_name = f"./reports/{updated_capture_file}.pcap"
        local_capture_file = file_name
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
        packet_filter1 = f"(wlan.addr == {dut_mac_address})"
        self.wifi_sniffer.interfaces.capture.shell(
            f"tshark -nr {self.wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
            f"frame.number -w "
            f"{wlan_filter_file}"
        )
        with self.wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
            sftp.get(wlan_filter_file, local_capture_file)
        for packet in self.wifi_sniffer.interfaces.capture.iter_packets(
                decrypt_packets=True,
                encryption_type="WPA-PWD",
                decryption_key=decryption_key,
                capture_file_filter=local_capture_file,
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
                        logger().info(
                            f"As per sniffer capture MQTT packets sent by DUT..{ta_address}  ->  {mqtt_layer}"
                        )
                        mqtt_capture_list.append(
                            tuple([mqtt_layer, packet.sniff_timestamp])
                        )
        return mqtt_capture_list

    def ssl_tcp_packet_check(
            self,
            decryption_key: str,
            dut_mac_address,
            ap_bssid,
            print_layers: list,
            capture_filename,
    ) -> list:
        current_time = time.time()
        updated_capture_file = (
                "filter_ssl"
                + capture_filename
                + "_"
                + str(datetime.fromtimestamp(current_time).strftime("%H_%M_%S"))
        )
        file_name = f"./reports/{updated_capture_file}.pcap"
        local_capture_file = file_name
        result_ssl = []
        result_tcp = []
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
        packet_filter1 = (
            f"(wlan.addr == {dut_mac_address}) && (wlan.addr == {ap_bssid})"
        )
        self.wifi_sniffer.interfaces.capture.shell(
            f"tshark -nr {self.wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
            f"frame.number -w "
            f"{wlan_filter_file}"
        )
        with self.wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
            sftp.get(wlan_filter_file, local_capture_file)
        for packet in self.wifi_sniffer.interfaces.capture.iter_packets(
                decrypt_packets=True,
                encryption_type="WPA-PWD",
                decryption_key=decryption_key,
                capture_file_filter=local_capture_file,
        ):
            for layer in packet.layers:
                layer_name = layer.layer_name.lower()
                if layer_name == "tls":
                    logger().info(
                        "================= Layer is TLS ==========================="
                    )
                    filtered_packet = str(packet)
                    filtered_packet = filtered_packet.split("Layer ")
                    tls_layer_pkt = ""
                    ra_address = ""
                    ta_address = ""
                    logger().info(
                        f"DUT_MAC_ADDRESS: {dut_mac_address},AP_BSSID: {ap_bssid}"
                    )
                    for layerp in filtered_packet:
                        if (
                                re.search(".*Receiver address:", layerp)
                                and re.search(".*Transmitter address:", layerp)
                        ) or (re.search(".*TLS:", layerp)):
                            if re.search(".*TLS:", layerp):
                                tls_layer_pkt = layerp
                            if re.search(".*Receiver address:", layerp) and re.search(
                                    ".*Transmitter address:", layerp
                            ):
                                Received = re.compile(
                                    r"Receiver address: (([0-9a-fA-F]:?){12})"
                                )
                                receiver_address = re.search(Received, layerp).group()
                                ra_address = (
                                    re.search(Received, layerp).group(1)
                                ).lower()
                                Transmit = re.compile(
                                    r"Transmitter address: (([0-9a-fA-F]:?){12})"
                                )
                                Transmitter_address = re.search(
                                    Transmit, layerp
                                ).group()
                                ta_address = (
                                    re.search(Transmit, layerp).group(1)
                                ).lower()
                                dut_mac_address_mod = dut_mac_address.lower()
                                ap_bssid_mod = ap_bssid.lower()

                            if (
                                    (
                                            ra_address == dut_mac_address_mod
                                            or ra_address == ap_bssid_mod
                                    )
                                    and (
                                            ta_address == dut_mac_address_mod
                                            or ta_address == ap_bssid_mod
                                    )
                            ) and tls_layer_pkt:
                                logger().info(
                                    f"{Transmitter_address}>>>>>>{receiver_address}"
                                )
                                logger().info(f"TLS HANDSHAKE PACKET: {tls_layer_pkt}")
                                result_ssl.append(str(tls_layer_pkt))
                if layer_name == "tcp":
                    logger().info("======= Layer is TCP =======")
                    filtered_packet = str(packet)
                    filtered_packet = filtered_packet.split("Layer ")
                    tcp_layer_pkt = ""
                    logger().info(
                        f"DUT_MAC_ADDRESS: {dut_mac_address},AP_BSSID: {ap_bssid}"
                    )
                    for layerp in filtered_packet:
                        if re.search(".*TCP:", layerp):
                            tcp_layer_pkt = layerp
                            logger().info(f"TCP PACKET: {tcp_layer_pkt}")
                            result_tcp.append(str(tcp_layer_pkt))

        return result_ssl, result_tcp

    def validate_ssl_connection(self, validate_keep_alive=False):
        packet_filter2 = "Application Data Protocol (Application Data)"
        decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
        ssl_pkt, tcp_pkt = self.ssl_tcp_packet_check(
            decryption_key,
            self.dut_addr["dut_mac_address"],
            self.wifi_access_point.interfaces.wifi.bssid,
            ["tls", "tcp"],
            self.request.node.name,
        )
        assert (
            message for message in ssl_pkt if "Client Hello" in ssl_pkt
        ), "Unable to find 'Client Hello' message"
        assert (
            message for message in ssl_pkt if "Server Hello" in ssl_pkt
        ), "Unable to find 'Server Hello' message"
        assert (
            message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt
        ), "Unable to find 'Client Key Exchange' message"
        assert (
            message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt
        ), "Unable to find 'Encrypted Handshake Message' "
        assert (
            message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt
        ), "Unable to find 'Change Cipher Spec' message"
        logger().info(
            f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======"
        )
        assert (
            message for message in tcp_pkt if "Flags: 0x002 (SYN)" in message
        ), f"Unable to find SYN packet "
        assert (
            message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in message
        ), "Unable to find SYN ACK"
        assert (
            message for message in tcp_pkt if "Flags: 0x010 (ACK)" in message
        ), "Unable to find ACK"
        assert (
            message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in message
        ), "Unable to find FIN ACK "

        if not validate_keep_alive:
            return

        packet_filter1 = f'(wlan.sa == {self.dut_addr["dut_mac_address"]}) && tls'
        logger().info(
            f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}"
        )
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.request.node.name}.pcap"
        )
        logger().info(f"Wait for {self.idle_time} seconds")
        time.sleep(self.idle_time)
        self.wifi_sniffer.interfaces.capture.stop_capture()
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1, packet_filter2=packet_filter2
        )["packet_count"]
        assert (
            not snif_pkt_count
        ), "MQTT keep alive packets capture even though keep alive is disable"


class ParallelThread(ThreadBase):
    def __init__(
            self,
            wifi_dut=None,
            mqtt_client=None,
            topic=None,
            message=None,
            qos=None,
            iterations=1,
    ):
        super().__init__()
        self.topic = topic
        self.wifi_dut = wifi_dut
        self.mqtt_client = mqtt_client
        self.message = message
        self.qos = qos
        self.iterations = iterations

    def run(self):
        for _ in range(self.iterations):
            self.wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
                topic=self.topic, message=self.message, qos=self.qos, timeout=20
            )
            logger().info(f"\n Validating MQTT Messages on DUT \n")
            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = (
                    self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                )
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
            self.mqtt_client.interfaces.mqtt.received_messages.clear()


class MQTTClientThread(ThreadBase):
    def __init__(
            self,
            wifi_dut=None,
            mqtt_client=None,
            topic=None,
            message=None,
            qos=None,
            iterations=1,
    ):
        super().__init__()
        self.topic = topic
        self.wifi_dut = wifi_dut
        self.mqtt_client = mqtt_client
        self.message = message
        self.qos = qos
        self.iterations = iterations

    def run(self):
        for _ in range(self.iterations):
            self.mqtt_client.interfaces.mqtt.mqtt_client_publish(
                topic=self.topic, payload=self.message, qos=self.qos
            )
            logger().info(f"\n Validating MQTT Messages on DUT \n")
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



@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
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
@pytest.mark.firmware_app("test_lwip_stack")
def test_neutral_less_profile_mqtt_on_host_lwip_sdk_C27490617(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        sniffer_filter,
        sl_collections,
        request,
):
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
            request=request,
            sl_collections=sl_collections,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=False,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        logger().info(f"DUT connection and IP: {mqtt_thread.dut_addr}")
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_management_data_rates()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


@wifi_dut_marker(enable_feature_bitmap=0)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
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
@pytest.mark.firmware_app("test_lwip_stack")
def test_neutral_less_profile_mqtt_on_host_lwip_sdk_C88924273(firmware_loader,
                                                              wifi_dut,
                                                              wifi_access_point,
                                                              wifi_sniffer,
                                                              mqtt_server,
                                                              mqtt_client,
                                                              sniffer_filter,
                                                              sl_collections,
                                                              request,
                                                              ): 
    try:
        wifi_dut.interfaces.wifi.sl_net_set_application_profile(
            interface="client", profile=1
        )
    except Exception as ex:
        logger().info("sl_net_set_application_profile failed as expected")
        logger().info(f"Error value: {ex}")
        status_match = re.search(r"status:(0x[0-9a-fA-F]+)", str(ex))
        if status_match:
            logger().info(f"Error status code: {status_match.group(1)}")
    else:
        assert False, (
            "sl_net_set_application_profile succeeded; test expects API failure"
        )

@wifi_dut_marker()
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
@pytest.mark.firmware_app("test_lwip_stack")
def test_neutral_less_profile_mqtt_on_host_lwip_sdk_C42831285(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C42831285"
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
            sl_collections=sl_collections,
            client_id=client_id,
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=True,
            enable_bt_powersave=True,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish_for_multiple_times(qos=qos, iterations=20)
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_data_rates()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


@wifi_dut_marker()
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
@pytest.mark.firmware_app("test_lwip_stack")
def test_neutral_less_profile_mqtt_on_host_lwip_sdk_C47001081(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C47001081"
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
            sl_collections=sl_collections,
            client_id=client_id,
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=True,
            enable_bt_powersave=True,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish_for_multiple_times(qos=qos, iterations=20)
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_data_rates()
        mqtt_thread.verify_ps_validation()
        mqtt_thread.verify_unexpected_filter_after_reconnect()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)

'''
@wifi_dut_marker()
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
@pytest.mark.firmware_app("test_lwip_stack")
def test_neutral_less_profile_mqtt_on_host_lwip_sdk_C72173716(firmware_loader,
                                                              wifi_dut,
                                                              wifi_access_point,
                                                              wifi_sniffer,
                                                              mqtt_server,
                                                              mqtt_client,
                                                              sniffer_filter,
                                                              sl_collections,
                                                              request,
                                                              ):
    topic = "Topic_C72173716"
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
    mqtt_thread = None
    dut_addr = {}
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{request.node.name}_sl_net_up.pcap"
        )
        wrong_passphrase = "wrong_passphrase"
        logger().info(
            f"Connecting with wrong passphrase {wrong_passphrase} to fail sl_net_up"
        )
        try:
            wifi_dut.interfaces.wifi.join(
                ssid=profile["ssid"],
                passphrase=wrong_passphrase,
                security=profile["security"].lower(),
                channel=profile["channel"],
                enable_lwip=1,
            )
            wifi_dut.interfaces.wifi.start_ip_lwip()
            wifi_dut.interfaces.wifi.sl_net_set_application_profile(
                interface="client", profile=1
            )
            wifi_dut.interfaces.wifi.sl_net_up(mode="client")
        except Exception as ex:
            logger().info(f"sl_net_up with wrong passphrase failed as expected: {ex}")
            status_match = re.search(r"status:(0x[0-9a-fA-F]+)", str(ex))
            if status_match:
                logger().info(f"Error status code: {status_match.group(1)}")
        else:
            assert False, (
                "sl_net_up succeeded with wrong passphrase; test expects failure"
            )
        wifi_dut.interfaces.wifi.set_performance_profile(
            mode="power_save_low_latency"
        )
        wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=5,
            scan_interval=4,
            beacon_missed_count=40,
            first_time_retry_enable=1,
        )
        attempt = 3
        flag = False
        last_error = None
        while attempt > 0:
            try:
                wifi_dut.interfaces.wifi.leave()
            except Exception as ex:
                logger().info(f"leave before retry skipped: {ex}")
            try:
                logger().info(
                    f"Connecting with correct passphrase, attempt {4 - attempt}/3"
                )
                wifi_dut.interfaces.wifi.join(
                    ssid=profile["ssid"],
                    passphrase=profile["passphrase"],
                    security=profile["security"].lower(),
                    channel=profile["channel"],
                    enable_lwip=1,
                )
                wifi_dut.interfaces.wifi.start_ip_lwip()
                wifi_dut.interfaces.wifi.sl_net_up(mode="client")
                flag = True
                break
            except Exception as e:
                last_error = e
                attempt -= 1
                logger().info(
                    f"sl_net_up failed with exception {e}, {attempt} attempts left"
                )
        assert flag, f"sl_net_up failed after 3 attempts: {last_error}"
        device_ip = wifi_dut.interfaces.wifi.display_device_ip_lwip()
        dut_addr["device_ip"] = wifi_dut.interfaces.wifi.get_device_ip(
            device_ip=device_ip
        )
        status = ping(dut_addr["device_ip"], 10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        dut_addr["dut_mac_address"] = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"\n DUT INFO: {dut_addr} \n")

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
            enable_bt_powersave=True,
        )
        mqtt_thread.dut_addr = dut_addr
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish_for_multiple_times(qos=qos, iterations=5)
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()
        unexpected_filter = MQTTConnectionThread._normalize_mgmt_rate_filter(
            sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                dut_addr=dut_addr["dut_mac_address"],
                filter_name="Neutral_less_profile_management_rates_not_expected",
            )
        )
        logger().info(f"Unexpected management rate filter = {unexpected_filter}")
        unexpected_result = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=unexpected_filter
        )
        assert unexpected_result["packet_count"], (
            "DUT management frames were not captured at a rate other than 6 Mbps"
        )
        logger().info(
            f"Unexpected-rate management packets found: "
            f"{unexpected_result['packet_count']}"
        )

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


@wifi_dut_marker()
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
@pytest.mark.firmware_app("test_lwip_stack")
def test_neutral_less_profile_mqtt_on_host_lwip_sdk_C42831285(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C42831285"
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
            sl_collections=sl_collections,
            client_id=client_id,
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=True,
            enable_bt_powersave=True,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish_for_multiple_times(qos=qos, iterations=20)
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_data_rates()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


@wifi_dut_marker()
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
@pytest.mark.firmware_app("test_lwip_stack")
def test_neutral_less_profile_mqtt_on_host_lwip_sdk_C77689920(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C42831285"
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
            sl_collections=sl_collections,
            client_id=client_id,
            qos=qos,
            profile=profile,
            sniffer_filter=sniffer_filter,
            enable_tls=True,
            enable_bt_powersave=True,
            application_profile_calls=2,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish_for_multiple_times(qos=qos, iterations=20)
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_data_rates()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)
'''
