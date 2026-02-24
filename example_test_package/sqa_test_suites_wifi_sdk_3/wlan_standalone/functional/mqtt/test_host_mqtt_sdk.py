import time
import pytest
import threading
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
    Si91xAesType, Si91xAesOperation, Si91xAesKeySize,
    Si91xKeyType, Si91xWrapIVMode,
    Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
)
from utf.interfaces.shell.ssh_shell import SSHShell
from utf.utils.logger import get_logger
import string
import re
import random
import concurrent.futures
from utf.utils.thread_base import ThreadBase
from threading import Thread
from typing import Dict
from datetime import datetime
import uuid
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils import get_tls_certificate_dir
from socket import gethostbyname
import concurrent.futures

"""The testcases added in this file can run below test steps :
        1. Configuration of DUT in 2G
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Open MQTT server in the Raspberry pi
        5. Connect to the MQTT server from the DUT
        6. Connect to the MQTT server from the Raspberry pi
        7. Send or receive data on MQTT and verify packet loss tests 

setup requirement:
        1. Soc Board
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC Wifi Sniffer 

Author : Bhargavi

"""

def logger():
    return get_logger(__name__)
WIFI_LOCK = threading.Lock()
class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, capture_filename=None, wifi_access_point=None, wifi_sniffer=None, mqtt_server=None
                 , mqtt_client=None, sl_collections=None, topic=None, sniffer_filter=None, message=None,
                 utf_constants=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.capture_filename = capture_filename
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.sl_collections = sl_collections
        self.dut_addr = None
        self.topic = topic
        self.sniffer_filter = sniffer_filter
        self.message = message
        self.keep_alive_time = None
        self.utf_constants = utf_constants

    def run(self):
        try:
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.
                                                                     channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")

            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)

            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated
                                                                     , ping_after_power_save=False,
                                                                     mode='power_save',
                                                                     listen_interval=1000)
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")

    def connect_to_mqtt_server(self, wifi_dut, mqtt_client, server_ip, port, qos):
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.paho_mqtt_set_advanced_configuration_command_handler(last_will_qos=qos)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_connect_to_server_command_handler(broker_address=server_ip,
                                                                                    broker_port=port,
                                                                                    client_id="Si91x_mqtt_client")
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(5)

    def dut_tx_topic1_and_host_tx_topic2_parallel_verify(
            self,
            wifi_dut,
            mqtt_client,
            topic1: str,
            topic2: str,
            dut_qos: int = 1,
            host_qos: int = 1,
            publish_count: int = 10,
            payload_length: int = 150,
            timeout_per_iter_sec: int = 10,
    ):
        import threading
        import time
        import random
        import string
        import re
        import traceback

        pattern = r"Topic:\s*(.*?),\s*Message:\s*(.*)"
        rx_re = re.compile(pattern, re.DOTALL)

        thread_errors = []
        dut_lock = threading.Lock()  # IMPORTANT: serialize DUT agent calls

        def _is_timeout_assertion(e: AssertionError) -> bool:
            s = str(e)
            return ("SL_STATUS_TIMEOUT" in s) or ("status:0x7" in s)

        def _dut_publish_with_retries(topic: str, payload: str, qos: int,
                                      retries: int = 5, sleep_sec: float = 0.3):
            last_e = None
            for attempt in range(1, retries + 1):
                try:
                    wifi_dut.interfaces.mqtt.paho_mqtt_client_publish_command_handler(
                        topic=topic,
                        msg_payload=payload,
                        qos_level=qos
                    )
                    return
                except AssertionError as e:
                    if _is_timeout_assertion(e):
                        logger().warning("[DUT publish] TIMEOUT attempt %d/%d, retrying...", attempt, retries)
                        last_e = e
                        time.sleep(sleep_sec)
                        continue
                    raise
            raise last_e

        def record_err(name: str, ex: Exception):
            thread_errors.append(f"{name} failed: {ex}\n{traceback.format_exc()}")

        # ---------------- Thread-1: DUT -> HOST ----------------
        def dut_tx_host_rx_thread():
            try:
                for i in range(1, publish_count + 1):
                    prefix = f"ITER{i}-DUT-T1-"
                    msg = prefix + "".join(
                        random.choices(string.ascii_uppercase + string.digits,
                                       k=max(0, payload_length - len(prefix)))
                    )

                    logger().info(f"[T1 DUT->HOST {i}/{publish_count}] DUT publishing topic1={topic1} qos={dut_qos}")

                    if hasattr(mqtt_client.interfaces.mqtt, "received_messages"):
                        mqtt_client.interfaces.mqtt.received_messages.clear()

                    # DUT publish (guarded + retries)
                    with dut_lock:
                        _dut_publish_with_retries(topic1, msg, dut_qos)

                    # Host wait for receive on topic1
                    start = time.time()
                    match = None
                    while (time.time() - start) < timeout_per_iter_sec:
                        time.sleep(0.1)
                        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

                        for m in reversed(msgs):
                            if getattr(m, "topic", None) == topic1:
                                match = m
                                break

                        if match is not None:
                            break

                    assert match is not None, (
                        f"[T1 DUT->HOST {i}] No message received on topic1={topic1} within {timeout_per_iter_sec}s"
                    )

                    rx_payload = match.payload
                    if isinstance(rx_payload, (bytes, bytearray)):
                        rx_payload = rx_payload.decode(errors="ignore")
                    rx_payload = str(rx_payload).strip("\r\n\0 ")
                    exp_payload = msg.strip("\r\n\0 ")

                    assert rx_payload == exp_payload, (
                        f"[T1 DUT->HOST {i}] Payload mismatch on topic1={topic1}\n"
                        f"EXPECTED(len={len(exp_payload)}): {exp_payload}\n"
                        f"RECEIVED(len={len(rx_payload)}): {rx_payload}\n"
                    )

                    logger().info(f"[T1 DUT->HOST {i}/{publish_count}] Host received & validated topic1 payload.")

            except Exception as ex:
                record_err("Thread-1 (DUT->HOST)", ex)

        # ---------------- Thread-2: HOST -> DUT ----------------
        def host_tx_dut_rx_thread():
            try:
                # non-greedy parser (handles multiple Topic/Message blocks in one yield)
                rx_re = re.compile(r"Topic:\s*(.+?)\s*,\s*Message:\s*(.+)")

                for i in range(1, publish_count + 1):
                    prefix = f"ITER{i}-HOST-T2-"
                    msg = prefix + "".join(
                        random.choices(string.ascii_uppercase + string.digits,
                                       k=max(0, payload_length - len(prefix)))
                    )

                    logger().info(f"[T2 HOST->DUT {i}/{publish_count}] Host publishing topic2={topic2} qos={host_qos}")
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic2, payload=msg, qos=host_qos)

                    start = time.time()
                    received_payload = None
                    last_with_topic = ""
                    last_non_empty = ""

                    while (time.time() - start) < timeout_per_iter_sec:
                        time.sleep(0.1)

                        # yield guarded by dut_lock; allow TIMEOUT
                        try:
                            with dut_lock:
                                out = wifi_dut.interfaces.mqtt.paho_mqtt_client_yield_command_handler(timeout_ms=10000)
                        except AssertionError as e:
                            if "SL_STATUS_TIMEOUT" in str(e) or "status:0x7" in str(e):
                                continue
                            raise

                        if isinstance(out, str) and out.strip():
                            last_non_empty = out
                        if isinstance(out, str) and "Topic:" in out:
                            last_with_topic = out

                            for t, m in rx_re.findall(out):
                                t = t.strip()
                                m = m.strip()

                                if t == topic2 and prefix in m:
                                    received_payload = m
                                    break

                        if received_payload is not None:
                            break

                    assert received_payload is not None, (
                        f"[T2 HOST->DUT {i}] DUT did not receive message on topic2={topic2} within {timeout_per_iter_sec}s\n"
                        f"Last non-empty yield output:\n{last_non_empty}\n\n"
                        f"Last yield output containing Topic:\n{last_with_topic}\n"
                    )

                    # Full payload validation (if DUT prints full payload)
                    # If DUT output truncates payload sometimes, change this to `assert msg.startswith(received_payload)`
                    assert received_payload == msg, (
                        f"[T2 HOST->DUT {i}] Payload mismatch on topic2={topic2}\n"
                        f"EXPECTED(len={len(msg)}): {msg}\n"
                        f"RECEIVED(len={len(received_payload)}): {received_payload}\n"
                    )

                    logger().info(f"[T2 HOST->DUT {i}/{publish_count}] DUT received & validated topic2 payload.")

            except Exception as ex:
                record_err("Thread-2 (HOST->DUT)", ex)

        t1 = threading.Thread(target=dut_tx_host_rx_thread, name="dut_tx_host_rx", daemon=True)
        t2 = threading.Thread(target=host_tx_dut_rx_thread, name="host_tx_dut_rx", daemon=True)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not thread_errors, "Parallel MQTT validation failed:\n\n" + "\n\n".join(thread_errors)

        logger().info("Parallel validation passed for %d iterations.", publish_count)

    def publish_and_verify_dut_rx_messages(self,
            wifi_dut,
            mqtt_client,
            topic: str,
            qos: int = 0,
            publish_count: int = 1,
            payload_length: int = 300,
            timeout_per_publish: int = 10
    ):
        """
        Publishes MQTT messages and verifies each one is received by DUT.

        :param wifi_dut: DUT object
        :param mqtt_client: MQTT client object
        :param topic: MQTT topic
        :param qos: QoS level (0/1/2)
        :param publish_count: Number of times to publish & verify
        :param payload_length: Length of random payload
        :param timeout_per_publish: Max wait time (seconds) per publish
        """
        topic_received = None
        message_received = None
        last_msgs = None
        pattern = r"Topic:\s*(.*?),\s*Message:\s*(.*)"

        for i in range(publish_count):
            # Generate payload
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=payload_length))

            logger().info(f"[{i + 1}/{publish_count}] Publishing message with QoS {qos}")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic, payload=message, qos=qos)

            start_time = time.time()

            while (time.time() - start_time) < timeout_per_publish:
                time.sleep(0.1)

                msgs = wifi_dut.interfaces.mqtt.paho_mqtt_client_yield_command_handler(timeout_ms=3000)

                last_msgs = msgs
                logger().info(f"[{i + 1}] Data received:\n{msgs}")

                if isinstance(msgs, str) and "Topic:" in msgs:
                    match = re.search(pattern, msgs, re.DOTALL)
                    if match:
                        topic_received = match.group(1).strip()
                        message_received = match.group(2).strip()
                        break

            # --- Assertions per publish ---
            assert topic_received is not None, (
                f"[{i + 1}] No parsable MQTT message received within {timeout_per_publish}s.\n"
                f"Last output:\n{last_msgs}"
            )

            assert topic_received == topic, (
                f"[{i + 1}] Topic mismatch: expected={topic}, got={topic_received}"
            )

            assert message_received == message, (
                f"[{i + 1}] Message mismatch or not received correctly."
            )

            logger().info(f"[{i + 1}/{publish_count}] Message received and validated successfully.")

        logger().info(f"All {publish_count} MQTT messages verified successfully.")

    def publish_and_verify_dut_rx_two_topics_parallel(
            self,
            wifi_dut,
            mqtt_client,
            topic1: str,
            topic2: str,
            qos: int = 1,
            publish_count: int = 10,
            payload_length: int = 300,
            timeout_per_iter_sec: int = 10,
    ):
        """
        Host publishes 2 messages (topic1 & topic2) per iteration.
        DUT yields and we verify DUT received BOTH topics for each iteration.
        Validates FULL payload equality.
        """

        # Non-greedy topic capture; message till end-of-line/block
        # This supports multiple occurrences in one yield output.
        pattern = r"Topic:\s*(.+?)\s*,\s*Message:\s*(.+)"
        rx_re = re.compile(pattern)

        for i in range(1, publish_count + 1):
            msg1 = f"ITER{i}-T1-" + "".join(
                random.choices(string.ascii_uppercase + string.digits, k=payload_length - len(f"ITER{i}-T1-")))
            msg2 = f"ITER{i}-T2-" + "".join(
                random.choices(string.ascii_uppercase + string.digits, k=payload_length - len(f"ITER{i}-T2-")))

            expected = {topic1: msg1, topic2: msg2}
            received = {}  # topic -> payload string

            logger().info(f"[{i}/{publish_count}] Publishing to topic1 and topic2 with QoS={qos}")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic1, payload=msg1, qos=qos)
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic2, payload=msg2, qos=qos)

            start = time.time()
            last_non_empty = ""
            last_with_topic = ""

            while time.time() - start < timeout_per_iter_sec:
                time.sleep(0.1)
                out = wifi_dut.interfaces.mqtt.paho_mqtt_client_yield_command_handler(timeout_ms=10000)

                # keep some debug context
                if isinstance(out, str) and out.strip():
                    last_non_empty = out
                if isinstance(out, str) and "Topic:" in out:
                    last_with_topic = out

                    # IMPORTANT: parse ALL occurrences in this output
                    for t, m in rx_re.findall(out):
                        t = t.strip()
                        m = m.strip()

                        # only store the topics we care about
                        if t in expected and t not in received:
                            received[t] = m

                if topic1 in received and topic2 in received:
                    break

            missing = [t for t in (topic1, topic2) if t not in received]
            assert not missing, (
                f"[{i}/{publish_count}] Missing messages on topics: {missing}\n"
                f"Received keys={list(received.keys())}\n"
                f"Last non-empty yield output:\n{last_non_empty}\n"
                f"\nLast yield output containing Topic:\n{last_with_topic}\n"
            )

            # FULL payload check (not first50)
            assert received[topic1] == expected[topic1], (
                f"[{i}/{publish_count}] Payload mismatch on topic1={topic1}\n"
                f"EXPECTED(len={len(expected[topic1])}): {expected[topic1]}\n"
                f"RECEIVED(len={len(received[topic1])}): {received[topic1]}\n"
            )

            assert received[topic2] == expected[topic2], (
                f"[{i}/{publish_count}] Payload mismatch on topic2={topic2}\n"
                f"EXPECTED(len={len(expected[topic2])}): {expected[topic2]}\n"
                f"RECEIVED(len={len(received[topic2])}): {received[topic2]}\n"
            )

            logger().info(f"[{i}/{publish_count}] Both topics received & validated successfully.")

    def dut_publish_and_verify_rx_on_host(self,
            wifi_dut,
            mqtt_client,
            topic: str,
            qos: int,
            publish_count: int = 10,
            payload_length: int = 150,
            timeout_per_publish_sec: int = 10,
    ):
        """
        DUT publishes publish_count messages.
        Host mqtt_client must receive and validate all publish_count messages.
        """

        for i in range(1, publish_count + 1):

            # Generate unique payload per iteration
            message = f"ITER{i}-" + ''.join(
                random.choices(string.ascii_uppercase + string.digits, k=payload_length - len(f"ITER{i}-"))
            )

            logger().info(f"[{i}/{publish_count}] Publishing from DUT")

            # Clear previous received messages before each publish
            mqtt_client.interfaces.mqtt.received_messages.clear()

            # DUT publish
            wifi_dut.interfaces.mqtt.paho_mqtt_client_publish_command_handler(
                topic=topic,
                msg_payload=message,
                qos_level=qos
            )

            # Wait for receive
            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < timeout_per_publish_sec:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) >= 1:
                    break

            assert len(msgs) >= 1, f"[{i}/{publish_count}] No message received by mqtt-client"

            # Find correct topic message (latest first)
            match = None
            for m in reversed(msgs):
                if m.topic == topic:
                    match = m
                    break

            assert match is not None, (
                f"[{i}/{publish_count}] No message received on expected topic={topic}"
            )

            # Decode payload safely
            rx_payload = match.payload.decode(errors="ignore")

            # Normalize common artifacts
            rx_payload = rx_payload.strip("\r\n\0 ")
            message = message.strip("\r\n\0 ")

            # Validate
            assert match.qos == qos, (
                f"[{i}/{publish_count}] QoS mismatch. expected={qos}, got={match.qos}"
            )

            assert rx_payload == message, (
                f"[{i}/{publish_count}] Payload mismatch.\n"
                f"Expected len={len(message)} tail={message[-20:]}\n"
                f"Received len={len(rx_payload)} tail={rx_payload[-20:]}"
            )

            logger().info(f"[{i}/{publish_count}] Message validated successfully")

        logger().info(f"All {publish_count} messages validated successfully")



def get_mqtt_list(self, dut_mac_address, decryption_key: str, print_layers: list) -> Dict[str, int]:
        mqtt_capture_list = []
        current_time = time.time()
        updated_capture_file = 'filter_' + self.capture_filename + '_' + str(
            datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
        file_name = f'./reports/{updated_capture_file}.pcap'
        local_capture_file = file_name
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
        packet_filter1 = f'(wlan.addr == {dut_mac_address})'
        self.wifi_sniffer.interfaces.capture.shell(
            f"tshark -nr {self.wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
            f"frame.number -w "
            f"{wlan_filter_file}")
        with self.wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
            sftp.get(wlan_filter_file, local_capture_file)
        for packet in self.wifi_sniffer.interfaces.capture.iter_packets(
                decrypt_packets=True,
                encryption_type="WPA-PWD",
                decryption_key=decryption_key,
                capture_file_filter=local_capture_file
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
                            f"As per sniffer capture MQTT packets sent by DUT..{ta_address}  ->  {mqtt_layer}")
                        mqtt_capture_list.append(tuple([mqtt_layer, packet.sniff_timestamp]))
        return mqtt_capture_list

class mqtt_publish_multiple_message_tx(ThreadBase):
    """
    Thread to publish data from DUT to mqtt server on subscribed topic and QOS value
    """

    def __init__(self, mqtt_client=None, wifi_dut=None, topic=None, qos=None, publish_count=1,
                 payload_length=150, timeout_per_publish=10):
        super().__init__()
        self.mqtt_client = mqtt_client
        self.wifi_dut = wifi_dut
        self.topic = topic
        self.qos = int(qos) if qos is not None else 0
        self.publish_count = int(publish_count) if publish_count is not None else 1
        self.payload_length = int(payload_length)
        self.timeout_per_publish = int(timeout_per_publish)

    def run(self):

        for i in range(1, self.publish_count + 1):

            # Generate unique payload per iteration
            message = f"ITER{i}-" + ''.join(
                random.choices(string.ascii_uppercase + string.digits, k=self.payload_length - len(f"ITER{i}-"))
            )

            logger().info(f"[{i}/{self.publish_count}] Publishing from DUT")

            # Clear previous received messages before each publish
            self.mqtt_client.interfaces.mqtt.received_messages.clear()


            # DUT publish
            self.wifi_dut.interfaces.mqtt.paho_mqtt_client_publish_command_handler(
                topic=self.topic,
                msg_payload=message,
                qos_level=self.qos
            )

            # Wait for receive
            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < self.timeout_per_publish:
                time.sleep(0.1)
                msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) >= 1:
                    break

            assert len(msgs) >= 1, f"[{i}/{self.publish_count}] No message received by mqtt-client"

            # Find correct topic message (latest first)
            match = None
            for m in reversed(msgs):
                if m.topic == self.topic:
                    match = m
                    break

            assert match is not None, (
                f"[{i}/{self.publish_count}] No message received on expected topic={self.topic}"
            )

            # Decode payload safely
            rx_payload = match.payload.decode(errors="ignore")

            # Normalize common artifacts
            rx_payload = rx_payload.strip("\r\n\0 ")
            message = message.strip("\r\n\0 ")

            # Validate
            assert match.qos == self.qos, (
                f"[{i}/{self.publish_count}] QoS mismatch. expected={self.qos}, got={match.qos}"
            )

            assert rx_payload == message, (
                f"[{i}/{self.publish_count}] Payload mismatch.\n"
                f"Expected len={len(message)} tail={message[-20:]}\n"
                f"Received len={len(rx_payload)} tail={rx_payload[-20:]}"
            )

            logger().info(f"[{i}/{self.publish_count}] Message validated successfully")

        logger().info(f"All {self.publish_count} messages validated successfully")

class mqtt_publish_multiple_messages_rx(ThreadBase):
    """
    Thread to receive data from mqtt server on subscribed topic and QOS value.
    """

    def __init__(self, mqtt_client=None, wifi_dut=None, topic=None, qos=None, publish_count=1,
                 payload_length=300, timeout_per_publish=10):
        super().__init__()
        self.mqtt_client = mqtt_client
        self.wifi_dut = wifi_dut
        self.topic = topic
        self.qos = int(qos) if qos is not None else 0
        self.publish_count = int(publish_count) if publish_count is not None else 1
        self.payload_length = int(payload_length)
        self.timeout_per_publish = int(timeout_per_publish)

    def run(self):
        pattern = r"Topic:\s*(.*?),\s*Message:\s*(.*)"

        for i in range(1, self.publish_count + 1):
            # Generate payload
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.payload_length))

            logger().info(f"[{i}/{self.publish_count}] Publishing message with QoS {self.qos}")
            self.mqtt_client.interfaces.mqtt.mqtt_client_publish(
                topic=self.topic, payload=message, qos=self.qos
            )

            topic_received = None
            message_received = None
            last_msgs = None
            start_time = time.time()

            while (time.time() - start_time) < self.timeout_per_publish:
                time.sleep(0.1)


                # with WIFI_LOCK:
                msgs = self.wifi_dut.interfaces.mqtt.paho_mqtt_client_yield_command_handler(timeout_ms=3000)

                last_msgs = msgs

                if isinstance(msgs, str) and "Topic:" in msgs:
                    match = re.search(pattern, msgs, re.DOTALL)
                    if match:
                        topic_received = match.group(1).strip()
                        message_received = match.group(2).strip()
                        break

            assert topic_received is not None, (
                f"[{i}] No parsable MQTT message received within {self.timeout_per_publish}s.\n"
                f"Last output:\n{last_msgs}"
            )
            assert topic_received == self.topic, (
                f"[{i}] Topic mismatch: expected={self.topic}, got={topic_received}"
            )
            assert message_received == message, (
                f"[{i}] Message mismatch.\n"
                f"Expected len={len(message)} tail={message[-20:]}\n"
                f"Received len={len(message_received)} tail={message_received[-20:]}"
            )

            logger().info(f"[{i}/{self.publish_count}] Message received and validated successfully.")

        logger().info(f"All {self.publish_count} MQTT messages verified successfully.")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_qos0_connect_subscribe_receive_TC777729(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client):
    """QOS0: Subscribe to MQTT server with TCP connection and publish data oversubscribed topic"""

    try:
        topic = "mytesttopic_C777729_" + str(uuid.uuid4())
        publish_count = 10
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj.connect_to_mqtt_server(wifi_dut,mqtt_client, server_ip, 1883, qos=0 )
        logger().info(".....Subscribe to the topic with Qos0 .....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(topic=topic, qos_level=0)
        logger().info(".....Check for the receive data when the mqtt client publish the messages with QoS0.....")

        mqtt_rx_obj = mqtt_publish_multiple_messages_rx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic=topic, qos=0, publish_count=publish_count )
        mqtt_rx_obj.start()
        mqtt_rx_obj.wait_for_exit()
        time.sleep(6*publish_count)
        # stop capture / unsubscribe as before
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic)
        time.sleep(1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
        # wifi_obj.verify_ps_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_qos1_connect_subscribe_receive_TC777730(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client):
    """QOS1: Subscribe to MQTT server with TCP connection and publish data oversubscribed topic"""

    try:
        topic = "mytesttopic_C777730_" + str(uuid.uuid4())
        publish_count = 10
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj.connect_to_mqtt_server(wifi_dut, mqtt_client, server_ip, 1883, qos=1)
        logger().info(".....Subscribe to the topic with Qos0 .....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(topic=topic, qos_level=1)
        logger().info(".....Check for the receive data when the mqtt client publish the messages with QoS1.....")
        mqtt_rx_obj = mqtt_publish_multiple_messages_rx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic=topic, qos=1,
                                                        publish_count=publish_count)
        mqtt_rx_obj.start()
        mqtt_rx_obj.wait_for_exit()
        time.sleep(6*publish_count)
        # stop capture / unsubscribe as before
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic)
        time.sleep(1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_qos0_connect_publish_receive_at_host_TC777731(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections,
        sniffer_filter, wifi_client):
    """QOS0: Subscribe to MQTT server with TCP connection and publish data oversubscribed topic"""

    try:
        topic = "mytesttopic_C777731_" + str(uuid.uuid4())
        publish_count=10
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=150))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                            wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj.connect_to_mqtt_server(wifi_dut, mqtt_client, server_ip, 1883, qos=0)
        logger().info("*************** MQTT Client subscribes to the topic *****************")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(topic=topic, qos_level=0)
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=0)
        time.sleep(10)
        logger().info(".....Check for the receive data at mqtt client when DUT publish the messages with QoS0.....")

        mqtt_tx_obj = mqtt_publish_multiple_message_tx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic=topic, qos=0,
                                                        publish_count=publish_count)
        mqtt_tx_obj.start()
        mqtt_tx_obj.wait_for_exit()
        time.sleep(6*publish_count)
        # stop capture / unsubscribe as before
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing MQTT_Client from the topic1....")
        mqtt_client.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
        # wifi_obj.verify_ps_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_qos1_connect_publish_receive_at_host_TC777732(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections,
        sniffer_filter, wifi_client):
    """QOS0: Subscribe to MQTT server with TCP connection and publish data oversubscribed topic"""

    try:
        topic = "mytesttopic_C777732_" + str(uuid.uuid4())
        publish_count=10
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=150))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                            wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj.connect_to_mqtt_server(wifi_dut, mqtt_client, server_ip, 1883, qos=1)
        logger().info("*************** MQTT Client subscribes to the topic *****************")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(topic=topic, qos_level=1)
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=1)
        time.sleep(10)
        logger().info(".....Check for the receive data at mqtt client when DUT publish the messages with QoS0.....")

        mqtt_tx_obj = mqtt_publish_multiple_message_tx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic=topic, qos=1,
                                                       publish_count=publish_count)
        mqtt_tx_obj.start()
        mqtt_tx_obj.wait_for_exit()
        time.sleep(6*publish_count)

        # stop capture / unsubscribe as before
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing MQTT_Client from the topic1....")
        mqtt_client.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
        # wifi_obj.verify_ps_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_qos1_dut_rx_two_topics_parallel_TC777734(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections,
        sniffer_filter, wifi_client):
    """QOS1: Subscribe to MQTT server with TCP connection and publish data oversubscribed topic"""

    try:
        topic1 = "mytesttopic1_C777734_" + str(uuid.uuid4())
        topic2 = "mytesttopic2_C777734_" + str(uuid.uuid4())
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                            wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic1,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        server_ip = wifi_client.interfaces.wifi.get_ip_address()

        wifi_obj.connect_to_mqtt_server(wifi_dut, mqtt_client, server_ip, 1883, qos=1)
        logger().info(".....Subscribe to the topic1 & topic2 with Qos1 .....")
        logger().info(".....Check for the receive data when the mqtt client publish the messages with QoS1.....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(topic=topic1, qos_level=1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(topic=topic2, qos_level=1)

        # Host publishes, DUT verifies receive
        wifi_obj.publish_and_verify_dut_rx_two_topics_parallel(
            wifi_dut=wifi_dut,
            mqtt_client=mqtt_client,
            topic1=topic1,
            topic2=topic2,
            qos=1,
            publish_count=10
        )
        # stop capture / unsubscribe as before
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic1)
        time.sleep(1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic2)
        time.sleep(1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_dut_tx_rx_two_topics_parallel_TC777735(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections,
        sniffer_filter, wifi_client):
    """QOS1: Subscribe to MQTT server with TCP connection and publish data oversubscribed topic"""

    try:
        topic1 = "mytesttopic1_C777735_" + str(uuid.uuid4())
        topic2 = "mytesttopic2_C777735_" + str(uuid.uuid4())
        publish_count=2
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=150))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                            wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic1,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        server_ip = wifi_client.interfaces.wifi.get_ip_address()

        wifi_obj.connect_to_mqtt_server(wifi_dut, mqtt_client, server_ip, 1883, qos=1)

        logger().info(".....Check for the receive data when the mqtt client publish the messages with QoS1.....")
        logger().info(".....Subscribe to the topic1[mqtt-client] with Qos1 .....")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
        logger().info(".....Subscribe to the topic2[DUT] with Qos1 .....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(topic=topic2, qos_level=1)
        mqtt_tx_obj = mqtt_publish_multiple_message_tx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic=topic2, qos=0,
                                                       publish_count=publish_count)
        mqtt_rx_obj = mqtt_publish_multiple_message_tx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic=topic1, qos=0,
                                                       publish_count=publish_count)
        mqtt_tx_obj.start()
        mqtt_tx_obj.wait_for_exit()
        mqtt_tx_obj.start()
        mqtt_tx_obj.wait_for_exit()

        time.sleep(10 * publish_count)

        # stop capture / unsubscribe as before
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic[DUT]....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic1)
        time.sleep(1)
        logger().info("....Unsubscribing from the topic[mqtt client]....")
        mqtt_client.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2)
        time.sleep(1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

