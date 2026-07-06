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
Author: Achal Raghav

Description:
This file contains Pytest test cases for validating MQTT functionality on the Wi-Fi SDK
when running on host LWIP. The tests cover MQTT and MQTT-over-TLS connections,
subscribe/publish flows with various QOS levels, keep-alive behavior, and other scenarios.

Test Cases Overview:
\- C876776: MQTT subscribe/publish/disconnect with QOS0
\- C876777: MQTTS subscribe/publish/disconnect with QOS0
\- C876778: MQTT subscribe/publish/disconnect with QOS1
\- C876779: MQTTS subscribe/publish/disconnect with QOS1
\- C876780: MQTT subscribe/publish/disconnect with QOS2
\- C876781: MQTTS subscribe/publish/disconnect with QOS2
\- C876782: MQTTS publish using QOS1 on different topics using threads
\- C876783: MQTTS publish using QOS2 on different topics using threads
\- C876784: MQTTS publish/subscribe using different topics
\- C876785: MQTTS publish with max supported length QOS2
\- C876786: MQTTS keepalive functionality with zero keepalive time
\- C876787: MQTT keepalive functionality with 30sec keepalive time
\- C876791: MQTTS publish after rejoin successful
\- C876792: MQTTS connection after rejoin error event
\- C876793: MQTTS subscribe/publish with DHCP lease 120 secs
\- C876794: MQTT connection with last will and retained bit set
\- C876795: MQTTS subscription with single and multilevel wild characters
\- C876798: MQTTS connection with persistent and clean session
\- C876799: MQTTS negative scenario publish 1400 bytes message
\- C876800: MQTTS connection with empty client ID
\- C876801: MQTTS connection failure with invalid/expired certs
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


def wifi_dut_marker(
        tcp_feat_bit=0,
        wifi_stack_len=3584,
        thread_count=1,
        ca_cert=None,
        coex_mode=None,
        memory_mode=None,
):
    # Defaults match the standard test footprint. Individual tests can override
    # coex_mode / memory_mode when they need a leaner or larger host allocation
    # (e.g. host-side mbedTLS handshakes that are heap-hungry).
    if coex_mode is None:
        coex_mode = Si91xCoexMode.WLAN | Si91xCoexMode.BLE
    if memory_mode is None:
        memory_mode = Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
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
        self.dut_addr["device_ip"] = self.wifi_dut.interfaces.wifi.get_device_ip(
            device_ip=device_ip
        )
        status = ping(self.dut_addr["device_ip"], 10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        self.wifi_dut.interfaces.wifi.set_performance_profile(
            mode="power_save_low_latency"
        )
        # BT power save is only meaningful when the BT/BLE stack is present. For
        # WLAN-only tests (no BLE coex) the DUT rejects bt_power_save_profile with
        # 0xFFFFFFFF, so allow tests to skip it.
        if self.enable_bt_powersave:
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
            )
        logger().info("....PINGING DUT AFTER POWER-SAVE....")
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

    def subscribe_and_publish(self, qos):
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

    def mqtt_keep_alive_check(self, dut_mac_address, test_case_name):
        remote_capture_file = self.wifi_sniffer.interfaces.capture.remote_capture_file
        logger().info(f"capture file is:{remote_capture_file}")

        filter_files = "/tmp/filter_files"
        test_case = test_case_name
        filtered_file = f"{filter_files}/{test_case}_main_filter.pcap"
        self.wifi_sniffer.interfaces.capture.shell(
            f"sudo rm -rf {filter_files}; sudo mkdir {filter_files}; sudo chmod +777 {filter_files};"
        )
        filter1 = f'tshark -r {remote_capture_file} -Y "(wlan.addr eq {dut_mac_address})" -w {filtered_file}'
        logger().info("Creating filtered packets")
        self.wifi_sniffer.interfaces.capture.shell(filter1)

        logger().info("Getting the ping request and response")
        filter3 = (
            f'tshark -r {filtered_file} -Y "(wlan.addr eq {dut_mac_address}) && (mqtt.msgtype ==4 or mqtt.msgtype '
            f'== 12)" -Tfields -e "mqtt.msgtype" -e "frame.time" -e "frame.time_re'
            f'lative" > {filter_files}/mqtt_publish_ack_ping_req.txt'
        )
        self.wifi_sniffer.interfaces.capture.shell(filter3)
        if isinstance(self.wifi_sniffer.interfaces.capture.shell, SSHShell):
            with self.wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp_main:
                sftp_main.get(filtered_file, f"./reports/{test_case}_delta_filter.pcap")
                result_file = f"./reports/mqtt_publish_ack_ping_req.txt"
                sftp_main.get(
                    f"{filter_files}/mqtt_publish_ack_ping_req.txt", result_file
                )
                sftp_main.close()
        publish_ack = []
        ping_request = []
        with open(result_file) as f:
            for line in f:
                if int(line.split()[0]) == 4:
                    publish_ack.append(line.split()[-1])
                elif int(line.split()[0]) == 12:
                    ping_request.append(line.split()[-1])
        return publish_ack, ping_request


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
@pytest.mark.test_src_map_id('C876776')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtt_subscribe_publish_with_qos0_on_host_lwip_C876776(firmware_loader,
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
            enable_tls=False,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


# C876777 is a host-LWIP MQTTS test that stalled with SL_STATUS_TIMEOUT. The
# passing reference run (cli_log) used coex = WLAN-only and the base 192 kB
# memory mode (NWP 480K / M4 192K) - i.e. NO BLE/BT stacks and maximum NWP
# memory. This override matches that footprint exactly: WLAN-only, and the base
# memory mode (Feature192kBMemoryMode == 0, so no 256/320/384 bit is set).
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
        # "lwip_mqtt_disconnect",

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
@pytest.mark.test_src_map_id('C876777')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_subscribe_publish_with_qos0_on_host_lwip_C876777(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    """MQTTS QOS0 on host LWIP: connect with enable_ssl=1, subscribe QOS0, receive on topic."""
    topic = "Topic_C876777"
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
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


@wifi_dut_marker()
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
@pytest.mark.test_src_map_id('C876778')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtt_subscribe_publish_with_qos1_on_host_lwip_C876778(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C876778"
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
            enable_tls=False,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
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
@pytest.mark.test_src_map_id('C876779')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_subscribe_publish_with_qos1_on_host_lwip_C876779(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C876779"
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
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


@wifi_dut_marker()
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
@pytest.mark.WLAN_Dev_sanity_917
@pytest.mark.test_src_map_id('C876780')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtt_subscribe_publish_with_qos2_on_host_lwip_C876780(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C876780"
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
            enable_tls=False,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
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
@pytest.mark.test_src_map_id('C876781')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_subscribe_publish_with_qos2_on_host_lwip_C876781(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C876781"
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
        mqtt_thread.subscribe_and_publish(qos=qos)
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
    thread_count=2,
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
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
@pytest.mark.test_src_map_id('C876782')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_publish_using_qos1_on_diff_topics_using_threads_C876782(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    primary_topic = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=40)
    )
    secondary_topic = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=60)
    )
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
            topic=None,
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
        primary_thread = ParallelThread(
            wifi_dut=wifi_dut,
            mqtt_client=mqtt_client,
            topic=primary_topic,
            message=message,
            qos=qos,
            iterations=3,
        )
        secondary_thread = ParallelThread(
            wifi_dut=wifi_dut,
            mqtt_client=mqtt_client,
            topic=secondary_topic,
            message=message,
            qos=qos,
            iterations=3,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=primary_topic, qos=qos)
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=primary_topic, qos=qos)
        wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=secondary_topic, qos=qos)
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(
            topic=secondary_topic, qos=qos
        )
        primary_thread.start()
        secondary_thread.start()
        primary_thread.wait_for_exit()
        secondary_thread.wait_for_exit()
        wifi_dut.interfaces.wifi.lwip_mqtt_unsubscribe(topic=primary_topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_unsubscribe(topic=secondary_topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        mqtt_thread.verify_ps_validation()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


@wifi_dut_marker(
    tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
    coex_mode=Si91xCoexMode.WLANOnly,
    memory_mode=Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
    thread_count=2,
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
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
@pytest.mark.test_src_map_id('C876783')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_publish_using_qos2_on_diff_topics_using_threads_C876783(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    primary_topic = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=10)
    )
    secondary_topic = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=15)
    )
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
    mqtt_thread = None
    try:
        mqtt_thread = MQTTConnectionThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            topic=None,
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
        primary_thread = ParallelThread(
            wifi_dut=wifi_dut,
            mqtt_client=mqtt_client,
            topic=primary_topic,
            message=message,
            qos=qos,
            iterations=3,
        )
        secondary_thread = ParallelThread(
            wifi_dut=wifi_dut,
            mqtt_client=mqtt_client,
            topic=secondary_topic,
            message=message,
            qos=qos,
            iterations=3,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=primary_topic, qos=qos)
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=primary_topic, qos=qos)
        wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=secondary_topic, qos=qos)
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(
            topic=secondary_topic, qos=qos
        )
        primary_thread.start()
        secondary_thread.start()
        primary_thread.wait_for_exit()
        secondary_thread.wait_for_exit()
        wifi_dut.interfaces.wifi.lwip_mqtt_unsubscribe(topic=primary_topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_unsubscribe(topic=secondary_topic)
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
    thread_count=2,
    wifi_stack_len=4096,
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
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
@pytest.mark.test_src_map_id('C876784')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_publish_subscribe_using_different_topics_C876784(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    primary_topic = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=10)
    )
    secondary_topic = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=10)
    )
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
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
            topic=None,
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
        primary_thread = ParallelThread(
            wifi_dut=wifi_dut,
            mqtt_client=mqtt_client,
            topic=primary_topic,
            message=message,
            qos=Si91xMqttQos.QOS1,
            iterations=3,
        )
        secondary_thread = MQTTClientThread(
            wifi_dut=wifi_dut,
            mqtt_client=mqtt_client,
            topic=secondary_topic,
            message=message,
            qos=qos,
            iterations=3,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=secondary_topic, qos=qos)
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(
            topic=primary_topic, qos=Si91xMqttQos.QOS1
        )
        primary_thread.start()
        secondary_thread.start()
        primary_thread.wait_for_exit()
        secondary_thread.wait_for_exit()
        wifi_dut.interfaces.wifi.lwip_mqtt_unsubscribe(topic=secondary_topic)
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
@pytest.mark.test_src_map_id('C876785')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_publish_with_max_supported_length_qos2_C876785(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C876785"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=1400))
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
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=qos)
        wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=topic, qos=qos)
        wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
            topic=topic, message=message, qos=qos, timeout=20, higher_data_len=1
        )
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
@pytest.mark.parametrize("keep_alive_time,idle_time", [(0, 120)])
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
@pytest.mark.test_src_map_id('C876786')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_keepalive_functionality_with_zero_keepalive_time_C876786(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
        keep_alive_time,
        idle_time,
):
    topic = "Topic_C876786"
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
            keepalive_time=keep_alive_time,
            idle_time=idle_time,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        mqtt_thread.verify_ps_validation()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.validate_ssl_connection(validate_keep_alive=True)
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.parametrize("keep_alive_time, idle_time", [(30, 120)])
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
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.test_src_map_id('C876787')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtt_keepalive_functionality_with_30sec_keepalive_time_C876787(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
        keep_alive_time,
        idle_time,
):
    stop_evt.clear()
    topic = "Topic_C876787"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "OPEN",
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
            enable_tls=False,
            keepalive_time=keep_alive_time,
            idle_time=idle_time,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        yield_thread = threading.Thread(
            target=_mqtt_yield_loop, args=(wifi_dut, stop_evt), daemon=True
        )
        yield_thread.start()
        logger().info(f"Wait for {idle_time} seconds")
        time.sleep(idle_time)
        stop_evt.set()
        yield_thread.join(timeout=2.0)
        wifi_sniffer.interfaces.capture.stop_capture()
        publish_ack, ping_request = mqtt_thread.mqtt_keep_alive_check(
            mqtt_thread.dut_addr["dut_mac_address"], request.node.name
        )
        logger().info(f"ping request timestamps : {ping_request}")
        if len(ping_request) >= 1 and len(publish_ack) >= 1:
            logger().info(
                f"len of publish ack is {len(publish_ack)} and number of ping request packets observed is : {len(ping_request)} publish ack : {publish_ack}, ping request : {ping_request}"
            )
            assert (
                    (keep_alive_time - 5)
                    < (float(ping_request[0]) - float(publish_ack[-1]))
                    <= (keep_alive_time + 5)
            ), (
                f"mqtt ping request is not observed even after {keep_alive_time} is "
                f"exhausted or before {keep_alive_time - 5} "
            )
            logger().info(
                f"MQTT KEEP ALIVE CHECK FUNCTIONALITY ** PING REQUEST PACKET OBSERVED AT DIFFERENCE OF {(float(ping_request[0]) - float(publish_ack[-1]))} SECONDS"
            )

        if len(ping_request) > 1:
            for i in range(0, len(ping_request)):
                if i == len(ping_request) - 1:
                    break
                assert (
                        (keep_alive_time - 5)
                        < (float(ping_request[i + 1]) - float(ping_request[i]))
                        <= (keep_alive_time + 5)
                ), (
                    f"mqtt ping request is not observed even after {keep_alive_time} is "
                    f"exhausted or before {keep_alive_time - 5} and the ping re"
                    f"quest arrival time is {ping_request[i]} "
                )
                logger().info(
                    f"MQTT KEEP ALIVE CHECK FUNCTIONALITY ** PING REQUEST PACKET OBSERVED AT DIFFERENCE OF {(float(ping_request[i + 1]) - float(ping_request[i]))} SECONDS"
                )

        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
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
@pytest.mark.test_src_map_id('C876791')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_publish_after_rejoin_successful_C876791(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
        switch,
):
    topic = "Topic_C876791"
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
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,
            scan_interval=4,
            beacon_missed_count=40,
            first_time_retry_enable=0,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=qos)
        wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=topic, qos=qos)
        ap_power_off = False
        for _ in range(8):
            if ap_power_off:
                logger().info("\n Turning off the Access Point \n")
                switch.interfaces.pdu_switch.turn_off(delay=20)
                logger().info("\n Successfully Powered off the AP \n")
                switch.interfaces.pdu_switch.turn_on(delay=100)
                ap_power_off = False
                logger().info("\n AP Powered ON \n")
                status = sl_collections.ping(mqtt_thread.dut_addr["device_ip"], 30, 5)
                assert status, "\n PING TO DUT FAILED \n"
            else:
                logger().info(f"DUT publishes message over mqtt topic --> {topic}")
                wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
                    topic=topic, message=message, qos=qos, timeout=20
                )
                yield_data = wifi_dut.interfaces.mqtt.lwip_mqtt_yield(
                    yield_timeout_ms=2000
                )
                pattern = re.compile(
                    r"Topic:\s*(?P<Topic>[^,]+),\s*Message:\s*(?P<Message>[^\r\n]+)",
                    re.DOTALL,
                )
                match = pattern.search(yield_data)
                if match:
                    yield_topic = match.group("Topic")
                    yield_message = match.group("Message")
                    logger().info(
                        f"Received MQTT message on DUT - Topic: {yield_topic}, Message: {yield_message}"
                    )
                    assert (
                            yield_topic == topic
                    ), "Mismatch in MQTT topic received on DUT"
                    assert (
                            yield_message == message
                    ), "Mismatch in MQTT message received on DUT"
                else:
                    raise AssertionError("No MQTT message received on DUT")
                if _ == 4:
                    ap_power_off = True
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()
        mqtt_thread.validate_ssl_connection()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread, switch=switch)


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
@pytest.mark.test_src_map_id('C876792')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_connection_after_rejoin_error_event_C876792(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
        switch,
):
    topic = "Topic_C876792"
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
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=5,
            scan_interval=4,
            beacon_missed_count=40,
            first_time_retry_enable=0,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.mqtt_connect()
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=qos)
        wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=topic, qos=qos)
        ap_power_off = False
        for _ in range(8):
            if ap_power_off:
                logger().info("\n Turning off the Access Point \n")
                switch.interfaces.pdu_switch.turn_off(delay=20)
                time.sleep(60)
                mqtt_thread.rejoin_async_event()
                logger().info("\n Successfully Powered off the AP \n")
                switch.interfaces.pdu_switch.turn_on(delay=100)
                ap_power_off = False
                logger().info("\n AP Powered ON \n")
                wifi_dut.interfaces.wifi.join(
                    ssid=profile["ssid"],
                    passphrase=profile["passphrase"],
                    security=profile["security"].lower(),
                    channel=profile["channel"],
                    enable_lwip=1,
                )
                wifi_dut.interfaces.wifi.start_ip_lwip()
                attempt = 3
                flag = False
                while attempt > 0:
                    try:
                        wifi_dut.interfaces.wifi.sl_net_up(mode="client")
                        flag = True
                    except Exception as e:
                        attempt -= 1
                        logger().info(
                            f"sl_net_up failed with exception {e}, retrying...{attempt} attempts left"
                        )
                    if flag:
                        break
                device_ip = wifi_dut.interfaces.wifi.display_device_ip_lwip()
                mqtt_thread.dut_addr["device_ip"] = (
                    wifi_dut.interfaces.wifi.get_device_ip(device_ip=device_ip)
                )
                status = sl_collections.ping(mqtt_thread.dut_addr["device_ip"], 30, 5)
                assert status, "\n PING TO DUT FAILED \n"
            else:
                logger().info(f"DUT publishes message over mqtt topic --> {topic}")
                wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
                    topic=topic, message=message, qos=qos, timeout=20
                )
                yield_data = wifi_dut.interfaces.mqtt.lwip_mqtt_yield(
                    yield_timeout_ms=2000
                )
                pattern = re.compile(
                    r"Topic:\s*(?P<Topic>[^,]+),\s*Message:\s*(?P<Message>[^\r\n]+)",
                    re.DOTALL,
                )
                match = pattern.search(yield_data)
                if match:
                    yield_topic = match.group("Topic")
                    yield_message = match.group("Message")
                    logger().info(
                        f"Received MQTT message on DUT - Topic: {yield_topic}, Message: {yield_message}"
                    )
                    assert (
                            yield_topic == topic
                    ), "Mismatch in MQTT topic received on DUT"
                    assert (
                            yield_message == message
                    ), "Mismatch in MQTT message received on DUT"
                else:
                    raise AssertionError("No MQTT message received on DUT")
                if _ == 4:
                    ap_power_off = True
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()
        mqtt_thread.validate_ssl_connection()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread, switch=switch)


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
        "lan_lease_time": 120,
    },
)
@pytest.mark.test_src_map_id('C876793')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_subscribe_publish_with_dhcp_lease_120_secs_c876793(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C876793"
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
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=qos)
        wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=topic, qos=qos)
        sw = Stopwatch()
        while sw.elapsed_sec < 300:
            wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
                topic=topic, message=message, qos=qos
            )
            mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()
        mqtt_thread.validate_ssl_connection()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.mqtt_server("raspi_mosquitto")
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
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.test_src_map_id('C876794')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtt_connection_with_last_will_and_retained_bit_set_c876794(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C876794"
    will_topic = "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
    will_message = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
    profile = {
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "OPEN",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    flag = False
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
            enable_tls=False,
        )
        mqtt_thread.start()
        mqtt_thread.wait_for_exit()
        mqtt_thread.lwip_mqtt_configure(
            will_topic=will_topic,
            will_message=will_message,
            enable_will=1,
            retain_will=1,
        )
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        current_time = time.time()
        updated_capture_file = (
                "filter_"
                + request.node.name
                + "_"
                + str(datetime.fromtimestamp(current_time).strftime("%H_%M_%S"))
        )
        file_name = f"./reports/{updated_capture_file}.pcap"
        local_capture_file = file_name
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
        packet_filter1 = f"(wlan.addr == {mqtt_thread.dut_addr['dut_mac_address']}) and (wlan.addr == {wifi_access_point.interfaces.wifi.bssid})"
        wifi_sniffer.interfaces.capture.shell(
            f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
            f"frame.number -w "
            f"{wlan_filter_file}"
        )
        with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
            sftp.get(wlan_filter_file, local_capture_file)
        for packet in wifi_sniffer.interfaces.capture.iter_packets(
                decrypt_packets=True,
                encryption_type="WPA-PWD",
                decryption_key=decryption_key,
                capture_file_filter=local_capture_file,
        ):
            for layer in packet.layers:
                layer_name = layer.layer_name.lower()
                if layer_name == "mqtt" and " Message Type: Connect Command" in str(
                        layer
                ):
                    mqtt_connect_text = str(layer)
                    logger().info(f"WLAN LAYER DATA : {mqtt_connect_text}")
                    WILL_RETAIN_SET_RE = re.compile(
                        r"(?im)^\s*\.\.1\.\s*\.\.\.\.\s*=\s*Will Retain:\s*Set\s*$"
                    )
                    WILL_FLAG_SET_RE = re.compile(
                        r"(?im)^\s*\.\.\.\.\s*\.1\.\.\s*=\s*Will Flag:\s*Set\s*$"
                    )
                    will_retain_set = bool(WILL_RETAIN_SET_RE.search(mqtt_connect_text))
                    will_flag_set = bool(WILL_FLAG_SET_RE.search(mqtt_connect_text))
                    assert (
                        will_retain_set
                    ), "Will Retain flag is not set in MQTT Connect packet"
                    assert will_flag_set, "Will Flag is not set in MQTT Connect packet"
                    flag = True
                    break
        assert flag, "MQTT Connect packet not found in the captured packets"

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
@pytest.mark.test_src_map_id('C876795')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_subscription_with_single_and_multilevel_wild_characters_c876795(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "sensors/+/temperature/#"
    published_topics = [
        "sensors/room1/temperature/outdoor/1",
        "sensors/room1/temperature/reading",
        "sensors/room1/temperature/test",
    ]
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
        wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=topic, qos=qos)
        for publish_topic in published_topics:
            mqtt_client.interfaces.mqtt.mqtt_client_publish(
                topic=publish_topic, payload=message, qos=qos
            )
            yield_data = wifi_dut.interfaces.mqtt.lwip_mqtt_yield(yield_timeout_ms=2000)
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
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()
        mqtt_thread.validate_ssl_connection()

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
@pytest.mark.test_src_map_id('C876798')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_connection_with_persistent_and_clean_session_c876798(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C876798"
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
        logger().info(f"\n Connecting with Persistent session \n")
        mqtt_thread.lwip_mqtt_configure(is_clean_session=0)
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        logger().info(f"\n Connecting with Clean session \n")
        mqtt_thread.lwip_mqtt_configure(is_clean_session=1)
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()
        mqtt_thread.validate_ssl_connection()

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
@pytest.mark.test_src_map_id('C876799')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_negative_scenario_publish_1400_bytes_message_c876799(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C876799"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "".join(random.choices(string.ascii_uppercase + string.digits, k=1700))
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
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=qos)
        wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=topic, qos=qos)
        output_data = wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
            topic=topic,
            message=message,
            qos=qos,
            timeout=20,
            higher_data_len=1,
            expected_status=SLStatus.SL_STATUS_FAIL,
        )
        if "MQTT Publish Failed: -1" in str(output_data):
            logger().info(
                "MQTT Publish failed as expected for larger than maximum supported message length"
            )
        else:
            raise AssertionError(
                "MQTT Publish did not fail for larger than maximum supported message length"
            )
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
@pytest.mark.test_src_map_id('C876800')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_connection_with_empty_client_id_c876800(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "Topic_C876800"
    client_id = "''"
    qos = Si91xMqttQos.QOS0
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
        mqtt_thread.lwip_mqtt_configure()
        mqtt_thread.mqtt_connect()
        mqtt_thread.subscribe_and_publish(qos=qos)
        mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()
        mqtt_thread.validate_ssl_connection()

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
@pytest.mark.test_src_map_id('C876801')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_connection_failure_with_invalid_expired_certs_c876801(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    topic = "".join(random.choices(string.ascii_uppercase + string.digits, k=500))
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
    message = "Topic_C876801"
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
        ca_cert_address, ca_cert_size = mqtt_thread.load_certificate(
            certificate="ca_test2.crt"
        )
        server_cert_address, server_cert_size = mqtt_thread.load_certificate(
            certificate="mosquitto-utf.silabs.com.cert.pem"
        )
        server_key_address, server_key_size = mqtt_thread.load_certificate(
            certificate="mosquitto-utf.silabs.com.key.pem"
        )
        wifi_dut.interfaces.wifi.lwip_mqtt_configure(
            ca_cert=ca_cert_address,
            client_cert=server_cert_address,
            client_key=server_key_address,
            ca_cert_size=ca_cert_size,
            client_cert_size=server_cert_size,
            client_key_size=server_key_size,
        )
        mqtt_thread.mqtt_connect(
            expected_status=SLStatus.SL_STATUS_FAIL,
            configure_tls_certs=False,
        )

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
@pytest.mark.test_src_map_id('C876803')
@pytest.mark.firmware_app("test_lwip_stack")
def test_mqtts_subscription_over_4_topics_with_retain_c876803(firmware_loader,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        mqtt_server,
        mqtt_client,
        sniffer_filter,
        sl_collections,
        request,
):
    retain = 1
    topic1 = "Topic1/C876803"
    topic2 = "Topic2/C876803"
    topic3 = "Topic3/C876803"
    topic4 = "Topic4/C876803"
    client_id = "Si91x_mqtt_client"
    qos = Si91xMqttQos.QOS2
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
            topic=None,
            request=request,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            message=None,
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
        for topic in [topic1, topic2, topic3, topic4]:
            message = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=100)
            )
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=qos)
            wifi_dut.interfaces.mqtt.lwip_mqtt_subscribe(topic=topic, qos=qos)
            wifi_dut.interfaces.mqtt.lwip_mqtt_publish(
                topic=topic, message=message, qos=qos, timeout=20, retain=retain
            )
            mqtt_thread.message = message
            mqtt_thread.topic = topic
            mqtt_thread.validate_mqtt_messages()
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic1)
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic2)
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic3)
        wifi_dut.interfaces.mqtt.lwip_mqtt_unsubscribe(topic=topic4)
        wifi_dut.interfaces.wifi.lwip_mqtt_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_thread.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        _mqtt_host_lwip_cleanup(wifi_dut, mqtt_thread=mqtt_thread)
