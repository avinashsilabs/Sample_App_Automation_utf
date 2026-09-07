import os
import time
import pytest
import string
import re
import random
from utf.utils.iperf.iperf_utils import ping
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

Test Cases Overview:
- C84889629: Long-run MQTTS QOS1: keep retrying WLAN join until AP is found, subscribe/publish for 6 hours at 5-60s intervals, recover from rejoin, then verify data rates, power-save and fail if any rejoin occurred

"""

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


class MQTTConnectionThread(ThreadBase):
    def __init__(
            self,
            wifi_dut=None,
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
            sniffer_channel=None,
            connect_retry_delay=30,
            connect_timeout_seconds=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
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
        self.rejoin_occurred = False
        self.rejoin_count = 0
        self.sniffer_channel = (
            sniffer_channel
            if sniffer_channel is not None
            else (self.profile or {}).get("channel", 1)
        )
        # connect_timeout_seconds=None keeps retrying until the AP is found.
        self.connect_retry_delay = connect_retry_delay
        self.connect_timeout_seconds = connect_timeout_seconds

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

    def enable_power_save(self, mode="power_save_low_latency"):
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode=mode)
        if self.enable_bt_powersave:
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
            )

    def _wlan_connect_once(self):
        """One full association attempt: join, LWIP IP, Neutral-less profile, sl_net_up."""
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
        self.enable_power_save()
        self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=5,
            scan_interval=4,
            beacon_missed_count=40,
            first_time_retry_enable=1,
        )
        attempt = 3
        last_error = None
        while attempt > 0:
            try:
                self.wifi_dut.interfaces.wifi.sl_net_up(mode="client")
                return
            except Exception as e:
                last_error = e
                attempt -= 1
                logger().info(
                    f"sl_net_up failed with exception {e}, {attempt} attempts left"
                )
                logger().info(
                    "sl_net_up failed, calling sl_net_set_application_profile before retry"
                )
                '''If the connection fails, we need to disable power-saving mode and re-enable it after calling Set Application Profile.'''
                self.wifi_dut.interfaces.wifi.set_performance_profile()
                self.wifi_dut.interfaces.wifi.sl_net_set_application_profile(
                    interface="client", profile=1
                )
                self.enable_power_save()
        raise AssertionError(f"sl_net_up failed after 3 attempts: {last_error}")

    def _reset_wlan_state(self):
        """Drop a partial association so the next join attempt starts clean."""
        try:
            self.wifi_dut.interfaces.wifi.sl_net_down(mode="client")
            return
        except Exception as ex:
            logger().warning(f"sl_net_down before WLAN retry skipped: {ex}")
        try:
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as ex:
            logger().warning(f"leave before WLAN retry skipped: {ex}")

    def connect_wlan_until_success(self):
        """Keep retrying association until the AP is found and the network is up."""
        sw = Stopwatch()
        cycle = 0
        while True:
            cycle += 1
            logger().info(
                f"\n WLAN connection attempt {cycle} to SSID {self.profile['ssid']} "
                f"on channel {self.profile['channel']} \n"
            )
            try:
                self._wlan_connect_once()
                logger().info(
                    f"\n DUT connected to {self.profile['ssid']} on attempt {cycle} "
                    f"after {sw.elapsed_sec:.0f}s \n"
                )
                return cycle
            except Exception as ex:
                logger().warning(
                    f"WLAN connection attempt {cycle} failed (AP not found or "
                    f"connection error): {ex}"
                )
                assert not self.wifi_dut.interfaces.wifi.is_dut_bad_state, (
                    f"DUT is in bad state after WLAN connection attempt {cycle}: {ex}"
                )
                if (
                    self.connect_timeout_seconds is not None
                    and sw.elapsed_sec >= self.connect_timeout_seconds
                ):
                    raise AssertionError(
                        f"DUT could not connect to {self.profile['ssid']} after "
                        f"{cycle} attempts / {sw.elapsed_sec:.0f}s"
                    ) from ex
                self._reset_wlan_state()
                logger().info(
                    f"Retrying WLAN connection in {self.connect_retry_delay}s"
                )
                time.sleep(self.connect_retry_delay)

    def run(self):
        logger().info(f"Starting sniffer on channel {self.sniffer_channel}")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.sniffer_channel
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.request.node.name}.pcap"
        )
        self.connect_wlan_until_success()
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
        sw = Stopwatch()
        while sw.elapsed_sec < 180:
            events = self.wifi_dut.interfaces.wifi.get_async_events()
            rejoin_error_events = [
                event
                for event in events
                if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT
            ]
            if len(rejoin_error_events):
                logger().info(
                    f"Received rejoin error event after {sw.elapsed_sec:.2f}s"
                )
                return True
            time.sleep(0.1)
        logger().info("Rejoin error async event was not received")
        return False

    def _subscribe_mqtt(self, qos):
        self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(
            topic=self.topic, qos=qos
        )
        self.wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=self.topic, qos=qos)
        self.mqtt_client.interfaces.mqtt.received_messages.clear()

    def _restart_wlan_connection(self):
        logger().info("\n Restarting WLAN connection after rejoin \n")
        self._reset_wlan_state()
        self.connect_wlan_until_success()
        device_ip = self.wifi_dut.interfaces.wifi.display_device_ip_lwip()
        self.dut_addr["device_ip"] = self.wifi_dut.interfaces.wifi.get_device_ip(
            device_ip=device_ip
        )
        status = ping(self.dut_addr["device_ip"], 10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST AFTER REJOIN"

    def _restart_mqtt_connection(self, qos):
        logger().info("\n Restarting MQTT connection after rejoin \n")
        try:
            self.wifi_dut.interfaces.mqtt.lwip_mqtt_disconnect()
        except Exception as ex:
            logger().warning(f"MQTT disconnect after rejoin skipped: {ex}")
        try:
            self.mqtt_client.interfaces.mqtt.mqtt_client_disconnect()
        except Exception as ex:
            logger().warning(f"Host MQTT client disconnect after rejoin skipped: {ex}")
        self.mqtt_connect()
        self._subscribe_mqtt(qos)
        logger().info("\n MQTT subscribe resumed after rejoin \n")

    def _check_and_handle_rejoin(self, qos):
        events = self.wifi_dut.interfaces.wifi.get_async_events(
            update_last_retrieved_timestamp=False
        )
        rejoin_error_events = [
            event
            for event in events
            if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT
        ]
        if not rejoin_error_events:
            return False
        self.rejoin_occurred = True
        self.rejoin_count += 1
        logger().info(
            "\n Rejoin detected on DUT during long run. "
            f"Calling rejoin_async_event() (count={self.rejoin_count}) \n"
        )
        self.rejoin_async_event()
        try:
            self.wifi_dut.interfaces.mqtt.lwip_mqtt_disconnect()
        except Exception as ex:
            logger().warning(f"MQTT disconnect before WLAN restart skipped: {ex}")
        self._restart_wlan_connection()
        self._restart_mqtt_connection(qos)
        logger().info(
            "\n WLAN and MQTT restarted after rejoin. Resuming data transfer \n"
        )
        return True

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

    def subscribe_and_publish_for_multiple_times(
            self, qos=None, iterations=50, duration_seconds=None, publish_intervals=None
    ):
        qos = qos if qos is not None else self.qos
        received_packet_count = 0
        publish_count = 0
        intervals = publish_intervals or list(range(5, 61, 5))
        self._subscribe_mqtt(qos)
        if duration_seconds is not None:
            logger().info(
                f"Publishing MQTT messages for {duration_seconds} seconds "
                f"with random intervals {intervals} seconds"
            )
            test_start_time = time.time()
            while (time.time() - test_start_time) < duration_seconds:
                if self._check_and_handle_rejoin(qos):
                    continue
                elapsed_seconds = int(time.time() - test_start_time)
                logger().info(
                    f"MQTT publish/receive {publish_count + 1}, elapsed {elapsed_seconds}s"
                )
                try:
                    self.wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
                        topic=self.topic,
                        message=self.message,
                        qos=qos,
                        timeout=20,
                        retain=self.retain,
                    )
                    received_packet_count += self._wait_for_host_mqtt_message()
                    received_packet_count += self._wait_for_dut_mqtt_message()
                except Exception as ex:
                    logger().warning(
                        f"MQTT data transfer failed during long run: {ex}"
                    )
                    time.sleep(2)
                    if self._check_and_handle_rejoin(qos):
                        continue
                    raise
                publish_count += 1
                logger().info(
                    f"MQTT receive packet count after publish {publish_count}: "
                    f"{received_packet_count}"
                )
                remaining_seconds = duration_seconds - (time.time() - test_start_time)
                if remaining_seconds <= 0:
                    break
                sleep_seconds = min(random.choice(intervals), remaining_seconds)
                logger().info(
                    f"Waiting {sleep_seconds} seconds before next MQTT publish"
                )
                remaining_wait = sleep_seconds
                while remaining_wait > 0:
                    if self._check_and_handle_rejoin(qos):
                        break
                    chunk = min(1.0, remaining_wait)
                    time.sleep(chunk)
                    remaining_wait -= chunk
            expected_packets = publish_count
        else:
            logger().info(
                f"Publishing MQTT messages {iterations} times to collect at least {iterations}  receive packets"
            )
            for count in range(1, iterations + 1):
                publish_count = count
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
            expected_packets = iterations
        assert received_packet_count >= expected_packets, (
            f"Expected at least {expected_packets} MQTT receive packets, got {received_packet_count}"
        )
        logger().info(
            f"MQTT multiple publish/receive completed. Total receive packets: {received_packet_count}"
        )
        return received_packet_count

    @staticmethod
    def _normalize_mgmt_rate_filter(packet_filter):
        packet_filter = packet_filter.strip().replace(")and (", ") and (")
        packet_filter = packet_filter.replace(")(", ") and (")
        while packet_filter.startswith("((") and packet_filter.count("(") > packet_filter.count(")"):
            packet_filter = packet_filter[1:]
        if packet_filter.count("(") > packet_filter.count(")"):
            packet_filter = packet_filter + (")" * (packet_filter.count("(") - packet_filter.count(")")))
        return packet_filter

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

    def assert_no_rejoin_occurred(self):
        events = self.wifi_dut.interfaces.wifi.get_async_events(
            update_last_retrieved_timestamp=False
        )
        leftover_rejoin_events = [
            event
            for event in events
            if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT
        ]
        if leftover_rejoin_events:
            self.rejoin_occurred = True
            self.rejoin_count += len(leftover_rejoin_events)
        assert not self.rejoin_occurred, (
            f"Rejoin event occurred during the test. "
            f"Rejoin count: {self.rejoin_count}"
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
@pytest.mark.firmware_app("test_lwip_stack")
def test_neutral_less_profile_mqtt_on_host_lwip_sdk_C84889629(firmware_loader,
        wifi_dut,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C84889629"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS1
    ssid = "Bhargavi"
    passphrase = "12345678"
    sniffer_channel = 6
    # Retry the WLAN connection forever until the AP is found.
    connect_retry_delay = 30
    connect_timeout_seconds = None
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    duration_hours = 6
    duration_seconds = duration_hours * 60 * 60
    publish_intervals = list(range(5, 61, 5))
    profile = {
        "ssid": ssid,
        "channel": sniffer_channel,
        "security": "WPA2",
        "passphrase": passphrase,
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    mqtt_thread = None
    try:
        mqtt_thread = MQTTConnectionThread(
            wifi_dut=wifi_dut,
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
            sniffer_channel=sniffer_channel,
            connect_retry_delay=connect_retry_delay,
            connect_timeout_seconds=connect_timeout_seconds,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish_for_multiple_times(
            qos=qos,
            duration_seconds=duration_seconds,
            publish_intervals=publish_intervals,
        )
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        time.sleep(2)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        time.sleep(2)
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_data_rates()
        mqtt_thread.verify_ps_validation()
        mqtt_thread.assert_no_rejoin_occurred()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)

