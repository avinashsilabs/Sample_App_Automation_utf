import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
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
)
from utf.interfaces.shell.ssh_shell import SSHShell
from utf.utils.logger import get_logger
import string
import re
import random
import concurrent.futures
from utf.utils.thread_base import ThreadBase
from typing import Dict
from datetime import datetime
import uuid
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils import get_tls_certificate_dir

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

Author : Saurabh Sharma

"""


def logger():
    return get_logger(__name__)

class HTTPSGET(ThreadBase):
    def __init__(self, wifi_dut=None, http_server=None, index_path=None, http_client=None, iter_count=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.http_server = http_server
        self.index_path = index_path
        self.http_client = http_client
        self.iter_count = iter_count
        self.server_port = None

    def run(self):
        for i in range(5):
            status_dut, content_dut = self.wifi_dut.interfaces.wifi.http_get(self.http_server.interfaces.http,
                                                                             self.index_path,
                                                                             server_port=self.server_port)
            status_client, content_client = self.http_client.interfaces.http.http_get(self.http_server.interfaces.http,
                                                                                      self.index_path)

            assert not status_dut, "failed to fetch the https data"
            assert content_dut, "failed to load the https data"

            logger().info(status_dut)
            logger().info(status_dut)

            assert content_dut == content_client, "\n Fetched Data from DUT and HTTP client are not same \n"
        status = self.wifi_dut.interfaces.wifi.http_client_deinit()
        if status == SLStatus.SL_STATUS_OK:
            self.http_client_initialized = False

    def http_client_init(self):
        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
        self.server_port = 443
        https_enable = True
        status = self.wifi_dut.interfaces.wifi.http_client_init(https_enable=https_enable, tls_version="tls_v_1_3")
        if status == SLStatus.SL_STATUS_OK:
            self.http_client_initialized = True


class MQTTParallelThread(ThreadBase):
    def __init__(self, wifi_dut=None, mqtt_server=None, mqtt_client=None, topic=None, message=None, iter_count=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.topic = topic
        self.message = message
        self.iter_count = iter_count
        self.message_address = None
        self.topic_address = None
        self.address_dict = {
            "topic": [],
            "message": [],
        }

    def run(self):
        logger().info(f"The address dict is {self.address_dict}")
        for topic_address, message_address in zip(self.address_dict['topic'], self.address_dict['message']):

            self.wifi_dut.interfaces.mqtt.mqtt_client_publish_allocate_mem(topic=self.topic, message=self.message,
                                                                           qos=1,
                                                                           timeout=100, load_mem=True,
                                                                           message_address=message_address,
                                                                           topic_address=topic_address)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

            assert msgs[0].topic == self.topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
            assert msgs[0].payload.decode() == self.message, "No message is received by mqtt-client on subscribed topic or " \
                                                                 "message received is wrong"

        logger().info("....Unsubscribing from the topic....")
        self.wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=self.topic)

    def mqtt_client_connect(self):
        for i in range(self.iter_count):
            if self.message is not None:
                self.message_address = self.wifi_dut.interfaces.wifi.allocate_memory(size=len(self.message) + 1)
                self.wifi_dut.interfaces.wifi.load_memory(address=self.message_address, size=len(self.message), write_content=self.message)
                self.address_dict['message'].append(self.message_address)
            if self.topic is not None:
                self.topic_address = self.wifi_dut.interfaces.wifi.allocate_memory(size=len(self.topic) + 1)
                self.wifi_dut.interfaces.wifi.load_memory(address=self.topic_address, size=len(self.topic), write_content=self.topic)
                self.address_dict['topic'].append(self.topic_address)

        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", server_port=8883, qos=1, is_connection_encrypted=True)
        logger().info(".....DUT connects to MQTT server.....")
        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(15)
        logger().info(".....MQTT Client connects to MQTT server.....")
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(5)
        logger().info("MQTT Client subscribes to the topic")
        self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic, qos=1)


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

            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")

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

    def ssl_tcp_packet_check(self, decryption_key: str, dut_mac_address, ap_bssid, print_layers: list,
                             capture_filename) -> list:
        current_time = time.time()
        updated_capture_file = 'filter_ssl' + capture_filename + '_' + str(datetime.fromtimestamp(current_time).
                                                                           strftime('%H_%M_%S'))
        file_name = f'./reports/{updated_capture_file}.pcap'
        local_capture_file = file_name
        result_ssl = []
        result_tcp = []
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {ap_bssid})'
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
                if layer_name == "tls":
                    logger().info("================= Layer is TLS ===========================")
                    filtered_packet = str(packet)
                    filtered_packet = filtered_packet.split("Layer ")
                    tls_layer_pkt = ""
                    ra_address = ""
                    ta_address = ""
                    logger().info(f"DUT_MAC_ADDRESS: {dut_mac_address},AP_BSSID: {ap_bssid}")
                    for layerp in filtered_packet:
                        if ((re.search(".*Receiver address:", layerp) and re.search(".*Transmitter address:", layerp))
                                or (re.search(".*TLS:", layerp))):
                            if re.search(".*TLS:", layerp):
                                tls_layer_pkt = layerp
                            if re.search(".*Receiver address:", layerp) and re.search(".*Transmitter address:", layerp):
                                Received = re.compile(r'Receiver address: (([0-9a-fA-F]:?){12})')
                                receiver_address = re.search(Received, layerp).group()
                                ra_address = (re.search(Received, layerp).group(1)).lower()
                                Transmit = re.compile(r'Transmitter address: (([0-9a-fA-F]:?){12})')
                                Transmitter_address = re.search(Transmit, layerp).group()
                                ta_address = (re.search(Transmit, layerp).group(1)).lower()
                                dut_mac_address_mod = dut_mac_address.lower()
                                ap_bssid_mod = ap_bssid.lower()

                            if ((ra_address == dut_mac_address_mod or ra_address == ap_bssid_mod) and (
                                    ta_address == dut_mac_address_mod or ta_address == ap_bssid_mod)) and tls_layer_pkt:
                                logger().info(f"{Transmitter_address}>>>>>>{receiver_address}")
                                logger().info(f"TLS HANDSHAKE PACKET: {tls_layer_pkt}")
                                result_ssl.append(str(tls_layer_pkt))
                if layer_name == "tcp":
                    logger().info("======= Layer is TCP =======")
                    filtered_packet = str(packet)
                    filtered_packet = filtered_packet.split("Layer ")
                    tcp_layer_pkt = ""
                    logger().info(f"DUT_MAC_ADDRESS: {dut_mac_address},AP_BSSID: {ap_bssid}")
                    for layerp in filtered_packet:
                        if re.search(".*TCP:", layerp):
                            tcp_layer_pkt = layerp
                            logger().info(f"TCP PACKET: {tcp_layer_pkt}")
                            result_tcp.append(str(tcp_layer_pkt))

        return result_ssl, result_tcp

    def subscribe_and_publish(self, qos):

        logger().info("MQTT Client subscribes to the topic")
        self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic, qos=qos)

        logger().info("DUT subscribes to the topic")
        self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic, qos=qos)

        time.sleep(5)

        logger().info("DUT publishes message over the topic")
        self.wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=self.topic, message=self.message, qos=qos, timeout=20)
        time.sleep(5)

    def verify_ps_validation(self):

        logger().info(f"Checking for the PS-Poll packets in the sniffer.")
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], filter_name='ps_poll')

        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"

    def mqtt_keep_alive_check(self, dut_mac_address, test_case_name):
        remote_capture_file = self.wifi_sniffer.interfaces.capture.remote_capture_file
        logger().info(f"capture file is:{remote_capture_file}")

        filter_files = "/tmp/filter_files"
        test_case = test_case_name
        filtered_file = f'{filter_files}/{test_case}_main_filter.pcap'
        self.wifi_sniffer.interfaces.capture.shell(
            f"sudo rm -rf {filter_files}; sudo mkdir {filter_files}; sudo chmod +777 {filter_files};")
        filter1 = f'tshark -r {remote_capture_file} -Y "(wlan.addr eq {dut_mac_address})" -w {filtered_file}'
        logger().info("Creating filtered packets")
        self.wifi_sniffer.interfaces.capture.shell(filter1)

        logger().info("Getting the ping request and response")
        filter3 = f'tshark -r {filtered_file} -Y "(wlan.addr eq {dut_mac_address}) && (mqtt.msgtype ==4 or mqtt.msgtype ' \
                  f'== 12)" -Tfields -e "mqtt.msgtype" -e "frame.time" -e "frame.time_re' \
                  f'lative" > {filter_files}/mqtt_publish_ack_ping_req.txt'
        self.wifi_sniffer.interfaces.capture.shell(filter3)
        if isinstance(self.wifi_sniffer.interfaces.capture.shell, SSHShell):
            with self.wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp_main:
                sftp_main.get(filtered_file, f"./reports/{test_case}_delta_filter.pcap")
                result_file = f"./reports/mqtt_publish_ack_ping_req.txt"
                sftp_main.get(f"{filter_files}/mqtt_publish_ack_ping_req.txt", result_file)
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

    def delta_between_tls_packet(self):

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        content = filter_file.read()
        content = re.findall(r"((?<=Time delta from previous captured frame:\s)[\d\.]+)", content)
        content = [float(x) for x in content]
        content = content[1:]
        logger().info(f'time_diff_list is {content}')
        for i in content:
            assert i / self.keep_alive_time < 1.09, "MQTT Keep Alive Packet missed or keep alive duration exceed"
        logger().info(f'MQTT keep alive packets captured successfully with keep alive time : {self.keep_alive_time}')

    def rejoin_async_event(self):
        logger().info("Checking for rejoin fail event from dut")
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


class mqtt_publish_message_tx(ThreadBase):
    """
    Thread to publish data from DUT to mqtt server on subscribed topic and QOS value
    """

    def __init__(self, wifi_dut=None, mqtt_client=None, topic1=None, topic2=None, message=None, qos=None,
                 utf_constants=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.mqtt_client = mqtt_client
        self.topic1 = topic1
        self.topic2 = topic2
        self.message = message
        self.qos = qos
        self.utf_constants = utf_constants

    def run(self):
        iter_count = self.utf_constants.get("iter_count")
        for count in range(iter_count):
            logger().info("********* DUT publishes message over the topic1 *********")
            self.wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=self.topic1, message=self.message, qos=self.qos,
                                                              timeout=20)
            time.sleep(5)

            logger().info("********* DUT publishes message over the topic2 *********")
            self.wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=self.topic2, message=self.message, qos=self.qos,
                                                              timeout=20)
            time.sleep(5)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 1:
            time.sleep(0.1)
            msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

        assert msgs[0].topic == self.topic1, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == self.qos, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == self.message, "No message is received by mqtt-client on subscribed topic or " \
                                                         "message received is wrong"

        msgss = []
        sw = Stopwatch()
        while sw.elapsed_sec < 1:
            time.sleep(0.1)
            msgss = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

        assert msgss[1].topic == self.topic2, "No message received by mqtt-client on subscribed topic"
        assert msgss[1].qos == self.qos, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgss[
                   1].payload.decode() == self.message, "No message is received by mqtt-client on subscribed topic or " \
                                                        "message received is wrong"


class mqtt_publish_message_tx_allocate_mem(ThreadBase):
    """
    Thread to publish data from DUT to mqtt server on subscribed topic and QOS value
    """

    def __init__(self, wifi_dut=None, mqtt_client=None, topic1=None, message=None, qos=None,
                 message_address=None, topic_address=None, load_mem=True):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.mqtt_client = mqtt_client
        self.topic1 = topic1
        self.message = message
        self.qos = qos
        self.message_address = message_address
        self.topic_address = topic_address
        self.load_mem = load_mem

    def run(self):
        iter_count = 2

        for count in range(iter_count):
            logger().info(f"Mqtt iteration {count}")
            logger().info("********* DUT publishes message over the topic1 *********")
            logger().info(f" Memory address for message {self.message_address}")
            logger().info(f" Memory address for topic {self.topic_address}")
            logger().info(f" Message is  {self.message}")
            logger().info(f" Topic is {self.topic1}")
            logger().info(f"Load_mem is {self.load_mem}")

            self.wifi_dut.interfaces.mqtt.mqtt_client_publish_allocate_mem(topic=self.topic1, message=self.message, qos=self.qos,
                                                              timeout=100, load_mem=self.load_mem,
                                                              message_address=self.message_address,
                                                              topic_address=self.topic_address)
            time.sleep(10)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 1:
            time.sleep(0.1)
            msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

        assert msgs[0].topic == self.topic1, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == self.qos, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == self.message, "No message is received by mqtt-client on subscribed topic or " \
                                                         "message received is wrong"

        time.sleep(15)


class mqtt_publish_message_rx(ThreadBase):
    """
    Thread to receive data from mqtt server on subscribed topic and QOS value.
    """

    def __init__(self, mqtt_client=None, wifi_dut=None, topic1=None, topic2=None, message=None, qos=None,
                 utf_constants=None):
        super().__init__()
        self.mqtt_client = mqtt_client
        self.wifi_dut = wifi_dut
        self.topic1 = topic1
        self.topic2 = topic2
        self.message = message
        self.qos = qos
        self.utf_constants = utf_constants

    def run(self):
        iter_count = self.utf_constants.get("iter_count")
        for count in range(iter_count):
            logger().info("********* MQTT Client publishes message over the topic1 **********")
            self.mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=self.topic1, payload=self.message, qos=self.qos)
            time.sleep(2)

            logger().info("********* MQTT Client publishes message over the topic2 *********")
            self.mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=self.topic2, payload=self.message, qos=self.qos)
            time.sleep(2)

    def dut_receive_check(self):
        found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 15:
            time.sleep(0.1)
            msgs = self.wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
            if self.topic1 or self.topic2 and self.message in msgs:
                found = True
            assert found
            break
        time.sleep(2)


class Iperf(ThreadBase):
    def __init__(self, wifi_dut=None, net_perf_client=None, wifi_client=None, protocol=None, traffic=None,
                 wifi_access_point=None, qos=None, capture_filename=None, wifi_sniffer=None, sl_collections=None,
                 sniffer_filter=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.traffic = traffic
        self.wifi_access_point = wifi_access_point
        self.qos = qos
        self.capture_filename = capture_filename
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.ap_mac_address = None
        self.host_ip = None

    def run(self):
        ip_config = self.wifi_dut.interfaces.wifi.start_ip()
        dut_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"******** HOST IP {self.host_ip} *******")
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"******** AP MAC ADDRESS {self.ap_mac_address} *******")

        self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip,
                                                             device_ip=dut_ip,
                                                             protocol=self.protocol, tos_value=self.traffic,
                                                             time_out=60)
        logger().info(
            f"Host IP: {self.host_ip}, Dut IP: {dut_ip}, Protocol: {self.protocol}, "
            f"tos_value: {self.traffic}")
        logger().info(f"***** starting iperf ******")
        self.net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** send traffic  ******")
        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                            local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            local_ip=dut_ip, remote_ip=self.host_ip,
                                            remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            size=1460, ttl=60, throughput_type=1, qos=self.qos, timeout=75)
        logger().info("data transfer is successful")
        time.sleep(3)


class mqttfunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, mqtt_server=None, mqtt_client=None, topic=None, message=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.topic = topic
        self.message = message

    def run(self):
        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", server_port=8883, qos=1, is_connection_encrypted=True)

        logger().info(".....DUT connects to MQTT server.....")
        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic")
        self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic, qos=1)

        logger().info("DUT subscribes to the topic")
        self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic, qos=1)

        time.sleep(5)

        logger().info("DUT publishes message over the topic")
        self.wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=self.topic, message=self.message, qos=1, timeout=20)
        time.sleep(5)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

        assert msgs[0].topic == self.topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == self.message, "No message is received by mqtt-client on subscribed topic or " \
                                                         "message received is wrong"

        logger().info("....Unsubscribing from the topic....")
        self.wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=self.topic)
        time.sleep(5)


class http_post(ThreadBase):
    def __init__(self, http_server=None, http_client=None, wifi_dut=None, index_path=None):
        super().__init__()
        self.http_server = http_server
        self.index_path = index_path
        self.wifi_dut = wifi_dut
        self.http_client = http_client

    def run(self):
        for i in range(3):
            logger().info(f"Http post iteration {i}")
            logger().info("**** http post ****")
            self.wifi_dut.interfaces.http.http_post_allocate_mem(self.http_server.interfaces.http, resource_path=self.index_path,
                                                    post_data="hellothisisfordifferenturlsusedtopostthed", load_mem=True)
            time.sleep(10)


class http_put(ThreadBase):
    def __init__(self, http_server=None, http_client=None, wifi_dut=None, index_path=None):
        super().__init__()
        self.http_server = http_server
        self.http_client = http_client
        self.wifi_dut = wifi_dut
        self.index_path = index_path

    def run(self):
        for i in range(2):
            logger().info(f"Htp put iteration {i}")
            logger().info("Enabling http client init process")
            self.wifi_dut.interfaces.wifi.http_client_init(https_enable=False)
            logger().info("**** http put ****")
            self.wifi_dut.interfaces.http.http_put_allocate_mem(self.http_server.interfaces.http, self.index_path, load_mem=True)
            time.sleep(5)
            logger().info("Enabling http deinit")
            self.wifi_dut.interfaces.wifi.http_client_deinit()
            time.sleep(3)


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
def test_wifi_sdk_mqtt_qos1_connect_subscribe_publish_TC127757(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """QOS1: Subscribe to MQTT server with TCP connection and publish data oversubscribed topic"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        wifi_obj.subscribe_and_publish(qos=Si91xMqttQos.QOS1)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
        wifi_obj.verify_ps_validation()
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
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_qos0_connect_publish_max_data_C127827(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, sniffer_filter, request, sl_collections):
    """QOS0: Subscribe to MQTT server with TCP connection and publish maximum data of 1000 bytes oversubscribed topic"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=0)

        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        time.sleep(25)

        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        wifi_obj.subscribe_and_publish(qos=Si91xMqttQos.QOS0)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS0, "DUT sent message with wrong QOS. expected is QOS0"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"

        logger().info(".....Unsubscribe from the topic.....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(3)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.verify_ps_validation()

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
def test_wifi_sdk_mqtt_retain_with_qos1_TC127826(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, sniffer_filter, request, sl_collections):
    """QOS1: Subscribe to MQTT server with TCP connection by enabling retain bit and publish data"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info(".....DUT connects to the mqtt server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT client connects to the mqtt server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        time.sleep(1)
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        logger().info(f"Publishing message with retain bit 1")
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1,
                                                     retain=Si91xMqttQos.QOS1, timeout=20)
        time.sleep(5)
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"Unsubscribing from the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
        wifi_obj.verify_ps_validation()
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_feature_not_enabled_error_0xFF74_TC127800(
        wifi_sniffer, mqtt_server, wifi_access_point, mqtt_client, wifi_dut, request, sl_collections, sniffer_filter):
    """If MQTT Feature is not enabled in DUT 0xFF74 error should be seen"""

    try:
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt,
                                                               mqtt_server="192.168.100.100",
                                                               expected_status=SLStatus.SL_STATUS_SI91X_FEATURE_NOT_ENABLED)
        logger().info(f"DUT sent error code 0x1ff74 when MQTT feature is not enabled which is expected")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_qos0_mqtt_with_tcp_publish_diff_length_C127791(
        wifi_sniffer, mqtt_server, mqtt_client, request, wifi_access_point, wifi_dut, sl_collections, sniffer_filter):
    """QOS0: Connect/subscribe to MQTT server with TCP connection and publish data with different lengths"""

    try:
        topic = "mytesttopic"
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                            wifi_access_point=wifi_access_point, sniffer_filter=sniffer_filter,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        client_devices = [wifi_dut, mqtt_client]
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=0)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        for device in client_devices:
            device.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        logger().info("MQTT client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS0)

        msg_length = [1, 10, 100, 512, 1000, 1390]

        for length in msg_length:
            logger().info(f" Publish data for length : {length} bytes")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            logger().info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS0,
                                                         timeout=20)
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[
                   0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                   "message received is wrong"
        assert msgs[
                   0].qos == Si91xMqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"

        logger().info("MQTT client unsubscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        mqtt_capture_list = wifi_obj.get_mqtt_list(wifi_obj.dut_addr['dut_mac_address'], decryption_key, ["mqtt"])
        logger().info(f" ===== Mqtt Capture list ========= {mqtt_capture_list}")
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_qos1_mqtt_with_tcp_publish_diff_length_C127792(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS1: Subscribe to MQTT server with TCP connection and publish data with different lengths"""

    try:
        topic = "mytesttopic"
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                            wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        client_devices = [wifi_dut, mqtt_client]
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        for device in client_devices:
            device.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        logger().info("MQTT client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        msg_length = [1, 10, 100, 512, 1000, 1390]
        for length in msg_length:
            logger().info(f" Publish data for length : {length} bytes")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            logger().info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1,
                                                         timeout=20)
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[
                   0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                   "message received is wrong"
        assert msgs[
                   0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"

        logger().info("MQTT client unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the sniffer")
        logger().info(
            f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
            f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        mqtt_capture_list = wifi_obj.get_mqtt_list(wifi_obj.dut_addr['dut_mac_address'], decryption_key, ["mqtt"])
        logger().info(f" ===== Mqtt Capture list ========= {mqtt_capture_list}")
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
@pytest.mark.config('wifi_access_point', wifi={"channel": 1, "security": 'OPEN'})
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(0, 120)])
def test_wifi_sdk_mqtt_keep_alive_disable_with_qos1_TC127794(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, keep_alive_time, idle_time, request,
        sl_collections, sniffer_filter):
    """QOS1: Subscribe to MQTT server with TCP connection and publish data. Check MQTT keep alive functionality when
    keep alive period is 0"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1,
                                                                        keep_alive_interval=keep_alive_time)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        wifi_obj.subscribe_and_publish(qos=Si91xMqttQos.QOS1)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS0"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"

        logger().info(f"Wait for {idle_time} seconds")
        time.sleep(idle_time)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)
        timestamp = []

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        mqtt_capture_list = wifi_obj.get_mqtt_list(wifi_obj.dut_addr['dut_mac_address'], decryption_key,
                                                   ["mqtt"])

        if not len(mqtt_capture_list):
            logger().info(f"MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the "
                          f"sniffer file")
            assert 0, "MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the sniffer " \
                      "file "
        for count in mqtt_capture_list:
            if "Ping Request" in count[0]:
                timestamp.append(count[1])
        assert len(timestamp) == 0, f"DUT is sending MQTT-KEEP alive packets even though feature is disabled"
        logger().info("As per sniffer capture no MQTT-KEEP alive packets  sent from DUT")

        logger().info("Unsubscribe from the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 1, "security": 'OPEN'})
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(60, 240)])
def test_wifi_sdk_mqtt_keep_alive_60_with_qos0_TC127761(wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point,
                                                        wifi_dut, keep_alive_time, idle_time, request, sl_collections):
    """QOS0: Subscribe to MQTT server with TCP connection and publish data. Verify MQTT keep alive functionality
    when keep alive period configured for 60 seconds"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, topic=topic, message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                        keep_alive_interval=keep_alive_time)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        wifi_obj.subscribe_and_publish(qos=Si91xMqttQos.QOS0)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS0, "DUT sent message with wrong QOS. expected is QOS0"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"
        logger().info(f"Wait for {idle_time} seconds")
        time.sleep(idle_time)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        publish_ack, ping_request = wifi_obj.mqtt_keep_alive_check(wifi_obj.dut_addr['dut_mac_address'],
                                                                   capture_filename)
        if len(ping_request) >= 1 and len(publish_ack) >= 1:
            logger().info(
                f"len of publish ack is {len(publish_ack)} and number of ping request packets observed is : {len(ping_request)} publish ack : {publish_ack}, ping request : {ping_request}")
            assert (keep_alive_time - 5) < (float(ping_request[0]) - float(publish_ack[-1])) <= (
                    keep_alive_time + 5), f"mqtt ping request is not observed even after {keep_alive_time} is " \
                                          f"exhausted or before {keep_alive_time - 5} "
            logger().info(
                f"MQTT KEEP ALIVE CHECK FUNCTIONALITY ** PING REQUEST PACKET OBSERVED AT DIFFERENCE OF {(float(ping_request[0]) - float(publish_ack[-1]))} SECONDS")

        if len(ping_request) > 1:
            for i in range(0, len(ping_request)):
                if i == len(ping_request) - 1:
                    break
                assert (keep_alive_time - 5) < (float(ping_request[i + 1]) - float(ping_request[i])) <= (
                        keep_alive_time + 5), f"mqtt ping request is not observed even after {keep_alive_time} is " \
                                              f"exhausted or before {keep_alive_time - 5} and the ping re" \
                                              f"quest arrival time is {ping_request[i]} "
                logger().info(
                    f"MQTT KEEP ALIVE CHECK FUNCTIONALITY ** PING REQUEST PACKET OBSERVED AT DIFFERENCE OF {(float(ping_request[i + 1]) - float(ping_request[i]))} SECONDS")

        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11, "security": 'OPEN'})
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(120, 480)])
def test_wifi_sdk_mqtt_keep_alive_120_with_qos1_TC127784(wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point,
                                                         wifi_dut, request, keep_alive_time, idle_time, sl_collections):
    """QOS1: Subscribe to MQTT server with TCP connection and publish data. Verify MQTT keep alive functionality
    when keep alive period configured for 120 seconds"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=250))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, topic=topic, message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1,
                                                                        keep_alive_interval=keep_alive_time)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        wifi_obj.subscribe_and_publish(qos=Si91xMqttQos.QOS1)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"

        logger().info(f"Wait for {idle_time} seconds")
        time.sleep(idle_time)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        publish_ack, ping_request = wifi_obj.mqtt_keep_alive_check(wifi_obj.dut_addr['dut_mac_address'],
                                                                   capture_filename)
        if len(ping_request) >= 1 and len(publish_ack) >= 1:
            logger().info(
                f"len of publish ack is {len(publish_ack)} and number of ping request packets observed is : {len(ping_request)} publish ack : {publish_ack}, ping request : {ping_request}")
            assert (keep_alive_time - 5) < (float(ping_request[0]) - float(publish_ack[-1])) <= (
                    keep_alive_time + 5), f"mqtt ping request is not observed even after {keep_alive_time} is " \
                                          f"exhausted or before {keep_alive_time - 5} "
            logger().info(
                f"MQTT KEEP ALIVE CHECK FUNCTIONALITY ** PING REQUEST PACKET OBSERVED AT DIFFERENCE OF {(float(ping_request[0]) - float(publish_ack[-1]))} SECONDS")

        if len(ping_request) > 1:
            for i in range(0, len(ping_request)):
                if i == len(ping_request) - 1:
                    break
                assert (keep_alive_time - 5) < (float(ping_request[i + 1]) - float(ping_request[i])) <= (
                        keep_alive_time + 5), f"mqtt ping request is not observed even after {keep_alive_time} is " \
                                              f"exhausted or before {keep_alive_time - 5} and the ping re" \
                                              f"quest arrival time is {ping_request[i]} "
                logger().info(
                    f"MQTT KEEP ALIVE CHECK FUNCTIONALITY ** PING REQUEST PACKET OBSERVED AT DIFFERENCE OF {(float(ping_request[i + 1]) - float(ping_request[i]))} SECONDS")

        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
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
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_mqtt_check_error_0x21_C127802(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, sniffer_filter, request, sl_collections, mqtt_client):
    """If topic is given more than 201 bytes 0x21 error code should be seen"""

    try:
        topic = ''.join(random.choices(string.ascii_uppercase + string.digits, k=205))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client")

        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1,
                                                       expected_status=SLStatus.SL_STATUS_INVALID_PARAMETER)
        logger().info("DUT sent 0x21 when the topic is more than 201 bytes")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'], device='reset')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_invalid_server_TC127801(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, sniffer_filter, request, sl_collections, mqtt_client):
    """If MQTT server is not running in PC and when DUT is trying to connect 0xFF87 error should be seen"""

    try:
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt,
                                                               mqtt_server="192.168.100.50")
        event_data1 = ""
        time.sleep(60)
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.TCP_CONNECTION_FAILURE_INDICATION:
                event_data1 = event.event_data

        logger().info(f"event data is {event_data1}")

        assert "0x1ff87" in event_data1, "expected error code not found. Expected is 0x1ff87"
        logger().info(f"MQTT server is not running at 192.168.100.50")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 6})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_server_with_ssl_conn_enable_retain_bit_publish_data_C127759(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS0: Subscribe to MQTT server with SSL connection by enabling retain bit and publish data"""

    try:
        topic = "mytesttopic"
        capture_filename = request.node.name
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=550))
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", server_port=8883,
                                                                        is_connection_encrypted=True, is_retained=True)
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        logger().info("==== MQTT client subscribes to the topic =====")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=Si91xMqttQos.QOS0)
        logger().info("=== Clear the previous received messages ===")
        mqtt_client.interfaces.mqtt.received_messages.clear()
        logger().info("===== DUT publishes message over the topic ======")
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS0,
                                                     retain=Si91xMqttQos.QOS1)
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[
                   0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message " \
                                                   "received is wrong"
        assert msgs[0].qos == Si91xMqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"

        logger().info("====== MQTT client unsubscribes to the topic =======")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(2)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
            f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename)
        assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
            "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt), \
            "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
            "Unable to find 'Change Cipher Spec' message"
        logger().info(f"===== TCP Packet decryprtion and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), \
            "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), \
            "Unable to find FIN ACK "
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_Connect_subscribe_to_MQTT_server_with_SSL_connection_and_publish_data_C127803(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS1: Connect/subscribe to MQTT server with SSL connection and publish data"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=400))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, topic=topic, message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                        server_port=8883, qos=1,
                                                                        is_connection_encrypted=True)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        mqtt_client.interfaces.mqtt.received_messages.clear()
        wifi_obj.subscribe_and_publish(qos=Si91xMqttQos.QOS1)
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"
        logger().info("MQTT client unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(2)
        logger().info("Disconnecting from MQTT Server")
        wifi_dut.interfaces.wifi.mqtt_client_disconnect()
        time.sleep(1)
        logger().info("Disconnecting from DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted"
            f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename)
        assert (message for message in ssl_pkt if
                "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if
                "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
            "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt), \
            "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
            "Unable to find 'Change Cipher Spec' message"
        logger().info(f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), \
            "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), \
            "Unable to find FIN ACK "
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_qos1_mqtt_with_ssl_publish_diff_length_C127789(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS1: Subscribe to MQTT server with SSL connection and publish data with different lengths"""

    try:
        topic = "mytesttopic"
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        client_devices = [wifi_dut, mqtt_client]
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1,
                                                                        server_port=8883, is_connection_encrypted=True)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        for device in client_devices:
            device.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info("MQTT client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        msg_length = [1, 10, 100, 512, 1000, 1350]
        for length in msg_length:
            logger().info(f" Publish data for length : {length} bytes")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            logger().info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1)
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[
                   0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                   "message received is wrong"
        assert msgs[
                   0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"
        logger().info("MQTT client unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the sniffer")
        logger().info(
            f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
            f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename)
        assert (message for message in ssl_pkt if
                "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if
                "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
            "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt), \
            "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
            "Unable to find 'Change Cipher Spec' message"
        logger().info(f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), \
            "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), \
            "Unable to find FIN ACK "
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 6})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_qos0_mqtt_with_ssl_publish_diff_length_C127790(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS0: Subscribe to MQTT server with SSL connection and publish data with different lengths"""

    try:
        topic = "mytesttopic"
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        client_devices = [wifi_dut, mqtt_client]
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", server_port=8883,
                                                                        is_connection_encrypted=True)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        for device in client_devices:
            device.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info("MQTT client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS0)

        msg_length = [1, 10, 100, 512, 1000, 1340]
        for length in msg_length:
            logger().info(f" Publish data for length : {length} bytes")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            logger().info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS0)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[
                   0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                   "message received is wrong"
        assert msgs[
                   0].qos == Si91xMqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"
        logger().info("MQTT client unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the sniffer")
        logger().info(
            f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
            f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename)
        assert (message for message in ssl_pkt if
                "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if
                "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
            "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt), \
            "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
            "Unable to find 'Change Cipher Spec' message"
        logger().info(f"===== TCP Packet decryprtion and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), \
            "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), \
            "Unable to find FIN ACK "
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11, "security": 'OPEN'})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(180, 720)])
def test_wifi_sdk_mqtt_keep_alive_180_ssl_connection_with_qos0_TC127786(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, keep_alive_time, idle_time,
        sl_collections):
    """QOS0: Subscribe to MQTT server with SSL connection and publish data. Check MQTT keep alive functionality
    when keep alive period is 180"""

    try:
        packet_filter2 = '    Type/Subtype: QoS Data (0x0028)'
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=400))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, topic=topic, message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.keep_alive_time = keep_alive_time
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                        keep_alive_interval=keep_alive_time,
                                                                        server_port=8883, is_connection_encrypted=True)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        wifi_obj.subscribe_and_publish(qos=Si91xMqttQos.QOS0)
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[
                   0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message" \
                                                   "received is wrong"
        assert msgs[0].qos == Si91xMqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        logger().info("Stopping the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename)
        assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if
                "Client Key Exchange" in ssl_pkt), "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if
                "Encrypted Handshake Message" in ssl_pkt), "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if
                "Change Cipher Spec" in ssl_pkt), "Unable to find 'Change Cipher Spec' message"
        logger().info(f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in message), f"Unable to find SYN packet "
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in message), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in message), "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in message), "Unable to find FIN ACK "

        packet_filter1 = f'(wlan.sa == {wifi_obj.dut_addr["dut_mac_address"]}) && tls'
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        logger().info(f"Wait for {idle_time} seconds")
        time.sleep(idle_time)
        wifi_sniffer.interfaces.capture.stop_capture()
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                            packet_filter2=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Application Data Protocol packets"

        logger().info("Unsubscribe from the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
        wifi_obj.delta_between_tls_packet()
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11, "security": 'OPEN'})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(0, 120)])
def test_wifi_sdk_mqtt_keep_alive_disable_ssl_connection_with_qos0_TC127795(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, keep_alive_time, idle_time,
        sl_collections):
    """QOS0: Subscribe to MQTT server with SSL connection and publish data. Check MQTT keep alive functionality
    when keep alive period is 0"""

    try:
        packet_filter2 = 'Application Data Protocol (Application Data)'
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=400))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, topic=topic, message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.keep_alive_time = keep_alive_time
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                        keep_alive_interval=keep_alive_time,
                                                                        server_port=8883, is_connection_encrypted=True)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        wifi_obj.subscribe_and_publish(qos=Si91xMqttQos.QOS0)
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[
                   0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message" \
                                                   "received is wrong"
        assert msgs[0].qos == Si91xMqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        logger().info("Stopping the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename)
        assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if
                "Client Key Exchange" in ssl_pkt), "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if
                "Encrypted Handshake Message" in ssl_pkt), "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if
                "Change Cipher Spec" in ssl_pkt), "Unable to find 'Change Cipher Spec' message"
        logger().info(f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in message), f"Unable to find SYN packet "
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in message), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in message), "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in message), "Unable to find FIN ACK "

        packet_filter1 = f'(wlan.sa == {wifi_obj.dut_addr["dut_mac_address"]}) && tls'
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.
                                                            channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        logger().info(f"Wait for {idle_time} seconds")
        time.sleep(idle_time)
        wifi_sniffer.interfaces.capture.stop_capture()
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                            packet_filter2=packet_filter2)[
            'packet_count']
        assert not snif_pkt_count, "MQTT keep alive packets capture even though keep alive is disable"

        logger().info("Unsubscribe from the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable"])
def test_wifi_sdk_connect_subscribe_publish_mqtt_with_ssl_qos1_for_30_min_C127798(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS1: Subscribe to MQTT server with SSL connection and publish data , initiate WLAN disconnection and
    do in a loop from scan/connect/ipconfig/subscribe/publish/disconnect for 30 minutes in loop"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=400))
        loop_watch = Stopwatch()
        while loop_watch.elapsed_sec < 1800:
            logger().info(
                f"============ {loop_watch.elapsed_sec} seconds are completed for connect, subscribe 400 bytes "
                f"of data publish and close ===========")
            capture_filename = request.node.name
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                                wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                                sl_collections=sl_collections)
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
            client_devices = [wifi_dut, mqtt_client]
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP BSSID = {ap_bssid}')
            mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f'DUT MAC ADDRESS = {mac_address}')
            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1,
                                                                            server_port=8883,
                                                                            is_connection_encrypted=True)
            logger().info("Both DUT and third-party mqtt client connects to MQTT server")
            for device in client_devices:
                device.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(25)

            logger().info("MQTT Client subscribes to the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
            logger().info("Wifi DUT subscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
            time.sleep(5)
            mqtt_client.interfaces.mqtt.received_messages.clear()
            logger().info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1)
            time.sleep(5)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) == 1:
                    break
            assert len(msgs) == 1, "No message is received by mqtt-client"
            assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[
                       0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message" \
                                                       "received is wrong"
            assert msgs[0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"

            logger().info("MQTT client unsubscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
            time.sleep(2)
            logger().info("Disconnecting from MQTT Server")
            wifi_dut.interfaces.wifi.mqtt_client_disconnect()
            time.sleep(3)
            wifi_dut.interfaces.wifi.leave()
            logger().info("Stop the sniffer")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info(
                f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
                f"Handshake Message ==============")
            decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
            logger().info(f"DECRYPTION KEY-->{decryption_key}")
            ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, wifi_obj.dut_addr['dut_mac_address'],
                                                             ap_bssid, ["tls", "tcp"], capture_filename)
            assert (message for message in ssl_pkt if
                    "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
            assert (message for message in ssl_pkt if
                    "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
            assert (message for message in ssl_pkt if
                    "Client Key Exchange" in ssl_pkt), "Unable to find 'Client Key Exchange' message"
            assert (message for message in ssl_pkt if
                    "Encrypted Handshake Message" in ssl_pkt), "Unable to find 'Encrypted Handshake Message' "
            assert (message for message in ssl_pkt if
                    "Change Cipher Spec" in ssl_pkt), "Unable to find 'Change Cipher Spec' message"
            logger().info(f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======")
            assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
            assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
            assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), "Unable to find ACK"
            assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), "Unable to find FIN ACK "
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable"])
def test_wifi_sdk_subscribe_mqtt_qos0_with_ssl_subscribe_unscribe_for_30_min_C127788(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS0: Subscribe to MQTT server with SSL connection and publish data. Unsubscribe from the subscribed topic and
    do the same Subscribe/Unsubscribe for 30 minutes in loop"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=400))
        loop_watch = Stopwatch()
        while loop_watch.elapsed_sec < 1800:
            logger().info(
                f"============ {loop_watch.elapsed_sec} seconds are completed for connect, subscribe 400 bytes "
                f"of data publish and close ===========")
            capture_filename = request.node.name
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                                wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                                sl_collections=sl_collections)
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
            client_devices = [wifi_dut, mqtt_client]
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP BSSID = {ap_bssid}')
            mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f'DUT MAC ADDRESS = {mac_address}')
            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=0,
                                                                            server_port=8883,
                                                                            is_connection_encrypted=True)
            logger().info("Both DUT and third-party mqtt client connects to MQTT server")
            for device in client_devices:
                device.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(25)

            logger().info("MQTT Client subscribes to the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS0)
            logger().info("Wifi DUT subscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS0)
            time.sleep(5)
            mqtt_client.interfaces.mqtt.received_messages.clear()
            logger().info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS0)
            time.sleep(5)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) == 1:
                    break
            assert len(msgs) == 1, "No message is received by mqtt-client"
            assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[
                       0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message" \
                                                       "received is wrong"
            assert msgs[0].qos == Si91xMqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"
            logger().info("MQTT client unsubscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
            time.sleep(1)
            logger().info("Disconnecting from MQTT Server")
            wifi_dut.interfaces.wifi.mqtt_client_disconnect()
            time.sleep(3)
            wifi_dut.interfaces.wifi.leave()
            logger().info("Stop the sniffer")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info(
                f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted"
                f"Handshake Message ==============")
            decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
            logger().info(f"DECRYPTION KEY-->{decryption_key}")
            ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, wifi_obj.dut_addr['dut_mac_address'],
                                                             ap_bssid, ["tls", "tcp"], capture_filename)
            assert (message for message in ssl_pkt if
                    "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
            assert (message for message in ssl_pkt if
                    "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
            assert (message for message in ssl_pkt if
                    "Client Key Exchange" in ssl_pkt), "Unable to find 'Client Key Exchange' message"
            assert (message for message in ssl_pkt if
                    "Encrypted Handshake Message" in ssl_pkt), "Unable to find 'Encrypted Handshake Message' "
            assert (message for message in ssl_pkt if
                    "Change Cipher Spec" in ssl_pkt), "Unable to find 'Change Cipher Spec' message"
            logger().info(f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======")
            assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
            assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
            assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), "Unable to find ACK"
            assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), "Unable to find FIN ACK "
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable"])
def test_wifi_sdk_qos1_subscribe_publish_disconnect_and_subscribe_again_30_min_C127796(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS1:Subscribe to MQTT server with TCP connection and publish data, disconnect from the topic and connect back"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))
        loop_watch = Stopwatch()
        while loop_watch.elapsed_sec < 1800:
            logger().info(
                f"============ {loop_watch.elapsed_sec} seconds are completed for connect, subscribe, 1000 bytes "
                f"of data publish and close ===========")
            capture_filename = request.node.name
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                                wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                                sl_collections=sl_collections)
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
            client_devices = [wifi_dut, mqtt_client]
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP BSSID = {ap_bssid}')
            mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f'DUT MAC ADDRESS = {mac_address}')
            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
            logger().info("Both DUT and third-party mqtt client connects to MQTT server")
            for device in client_devices:
                device.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(5)

            logger().info("Wifi DUT subscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
            time.sleep(1)
            mqtt_client.interfaces.mqtt.received_messages.clear()
            logger().info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1)
            time.sleep(5)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) == 1:
                    break
            assert len(msgs), "No message is received by DUT"
            assert msgs[0] == topic, "No message received by DUT on subscribed topic"
            assert msgs[
                       1] == message, "No message is received by DUT on subscribed topic or " \
                                      "message received is wrong"

            logger().info("MQTT client unsubscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
            time.sleep(1)
            logger().info("Disconnecting from MQTT Server")
            wifi_dut.interfaces.wifi.mqtt_client_disconnect()
            time.sleep(5)
            wifi_dut.interfaces.wifi.leave()
            logger().info("Stop the sniffer")
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info(
                f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
                f"Handshake Message ==============")
            decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
            logger().info(f"DECRYPTION KEY-->{decryption_key}")
            ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, mac_address,
                                                             ap_bssid, ["tls", "tcp"], capture_filename)
            logger().info(f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======")
            assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
            assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
            assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), \
                "Unable to find ACK"
            assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), \
                "Unable to find FIN ACK "

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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable"])
def test_wifi_sdk_qos0_subscribe_publish_disconnect_and_subscribe_again_for_30_min_C127793(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS0: Subscribe to MQTT server with TCP connection and publish 1300 bytes of data for 30 minutes continuously"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1300))
        loop_watch = Stopwatch()
        while loop_watch.elapsed_sec < 1800:
            logger().info(
                f"============ {loop_watch.elapsed_sec} seconds are completed for connect, subscribe, 1300 bytes "
                f"of data publish and close ===========")
            capture_filename = request.node.name
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                                wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                                sl_collections=sl_collections)
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
            client_devices = [wifi_dut, mqtt_client]
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP BSSID = {ap_bssid}')
            mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f'DUT MAC ADDRESS = {mac_address}')
            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=0)
            logger().info("Both DUT and third-party mqtt client connects to MQTT server")
            for device in client_devices:
                device.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(5)

            logger().info("Wifi DUT subscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS0)
            time.sleep(1)
            mqtt_client.interfaces.mqtt.received_messages.clear()
            logger().info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS0)
            time.sleep(5)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) == 1:
                    break
            assert len(msgs), "No message is received by dut"
            assert msgs[0] == topic, "No message received by DUT on subscribed topic"
            assert msgs[
                       1] == message, "No message is received by DUT on subscribed topic or " \
                                      "message received is wrong"

            logger().info("MQTT client unsubscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
            time.sleep(1)
            logger().info("Disconnecting from MQTT Server")
            wifi_dut.interfaces.wifi.mqtt_client_disconnect()
            time.sleep(5)
            wifi_dut.interfaces.wifi.leave()
            logger().info("Stop the sniffer")
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info(
                f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
                f"Handshake Message ==============")
            decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
            logger().info(f"DECRYPTION KEY-->{decryption_key}")
            ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, mac_address,
                                                             ap_bssid, ["tls", "tcp"], capture_filename)
            logger().info(f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======")
            assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
            assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
            assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), \
                "Unable to find ACK"
            assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), \
                "Unable to find FIN ACK "

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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 1, "security": 'OPEN'})
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(60, 43200)])
def test_wifi_sdk_mqtt_keep_alive_60_and_12_hours_with_qos0_TC127797(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, keep_alive_time, idle_time,
        sl_collections):
    """QOS0 : Subscribe to MQTT server with TCP connection and publish data. Verify MQTT keep alive functionality
    when keep alive period configured for 60 seconds"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, topic=topic, message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                        keep_alive_interval=keep_alive_time)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        wifi_obj.subscribe_and_publish(qos=Si91xMqttQos.QOS0)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[
                   0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message" \
                                                   "received is wrong"
        assert msgs[0].qos == Si91xMqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"

        logger().info(f"Wait for {idle_time} seconds")
        time.sleep(idle_time)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        publish_ack, ping_request = wifi_obj.mqtt_keep_alive_check(wifi_obj.dut_addr['dut_mac_address'],
                                                                   capture_filename)
        if len(ping_request) >= 1 and len(publish_ack) >= 1:
            logger().info(
                f"len of publish ack is {len(publish_ack)} and number of ping request packets observed is : {len(ping_request)} publish ack : {publish_ack}, ping request : {ping_request}")
            assert (keep_alive_time - 5) < (float(ping_request[0]) - float(publish_ack[-1])) <= (
                    keep_alive_time + 5), f"mqtt ping request is not observed even after {keep_alive_time} is " \
                                          f"exhausted or before {keep_alive_time - 5} "
            logger().info(
                f"MQTT KEEP ALIVE CHECK FUNCTIONALITY ** PING REQUEST PACKET OBSERVED AT DIFFERENCE OF {(float(ping_request[0]) - float(publish_ack[-1]))} SECONDS")

        if len(ping_request) > 1:
            for i in range(0, len(ping_request)):
                if i == len(ping_request) - 1:
                    break
                assert (keep_alive_time - 5) < (float(ping_request[i + 1]) - float(ping_request[i])) <= (
                        keep_alive_time + 5), f"mqtt ping request is not observed even after {keep_alive_time} is " \
                                              f"exhausted or before {keep_alive_time - 5} and the ping re" \
                                              f"quest arrival time is {ping_request[i]} "
                logger().info(
                    f"MQTT KEEP ALIVE CHECK FUNCTIONALITY ** PING REQUEST PACKET OBSERVED AT DIFFERENCE OF {(float(ping_request[i + 1]) - float(ping_request[i]))} SECONDS")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


""" ********************** The Below 3 Test Cases Requires PDU Setup ************************* """


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {

        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}}
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_connect_subscribe_MQTT_server_with_SSL_connection_rejoin_c127799(switch, wifi_sniffer, mqtt_server,
                                                                                   mqtt_client, wifi_access_point,
                                                                                   wifi_dut, request, sl_collections):
    """
    QOS1: Subscribe to MQTT server with SSL connection and publish data. check rejoin functionality after
    disconnecting from AP
    """
    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=600))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, topic=topic, message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        dut_ip = wifi_obj.dut_addr['device_ip']
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                        server_port=8883, qos=1,
                                                                        is_connection_encrypted=True)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        mqtt_client.interfaces.mqtt.received_messages.clear()
        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=1)
        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=1, timeout=30)
        time.sleep(5)

        ap_power_off = 0
        # Sending 4 mqtt messages before and after turning off AP
        for send_count in range(1, 9):
            if ap_power_off:
                logger().info("Turning off the AP")
                switch.interfaces.pdu_switch.turn_off(delay=20)
                # wifi_access_point.interfaces.wifi.stop_ap()
                # time.sleep(20)
                logger().info("Successfully powered off AP")

                logger().info("Again turning on the AP")
                switch.interfaces.pdu_switch.turn_on(delay=100)
                # wifi_access_point.interfaces.wifi.start_ap()
                # time.sleep(100)
                ap_power_off = 0
                logger().info("Successfully powered on AP")
                logger().info("Pinging to DUT to check rejoin process is completed or not")
                status = sl_collections.ping(dut_ip, 30, 5)
                assert status, "Pinging to DUT is failed, DUT not rejoined to AP"
            logger().info(f"DUT publishes message over mqtt topic --> {topic}")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=1, timeout=20)
            time.sleep(5)
            # turning off AP after sending 4 mqtt messages from DUT
            if send_count == 4:
                ap_power_off = 1

        time.sleep(2)
        logger().info("MQTT client unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted"
            f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename)
        assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if
                "Client Key Exchange" in ssl_pkt), "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if
                "Encrypted Handshake Message" in ssl_pkt), "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if
                "Change Cipher Spec" in ssl_pkt), "Unable to find 'Change Cipher Spec' message"
        logger().info(f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), "Unable to find FIN ACK "
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {

        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}}
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_connect_subscribe_MQTT_server_with_SSL_connection_rejoin_c127828(switch, wifi_sniffer, mqtt_server,
                                                                                   mqtt_client, wifi_access_point,
                                                                                   wifi_dut, request, sl_collections):
    """
    QOS1: Subscribe to MQTT server with SSL connection and publish maximum data of 1351 bytes oversubscribed topic
    and check the DUT behavior.
    """
    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1351))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, topic=topic, message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        dut_ip = wifi_obj.dut_addr['device_ip']
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                        server_port=8883, qos=1,
                                                                        is_connection_encrypted=True)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        mqtt_client.interfaces.mqtt.received_messages.clear()
        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=1)
        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=1, timeout=30)
        time.sleep(5)

        ap_power_off = 0
        # Sending 4 mqtt messages before and after turning off AP
        for send_count in range(1, 9):
            if ap_power_off:
                logger().info("Turning off the AP")
                switch.interfaces.pdu_switch.turn_off(delay=20)
                # wifi_access_point.interfaces.wifi.stop_ap()
                # time.sleep(20)
                logger().info("Successfully powered off AP")

                logger().info("Again turning on the AP")
                switch.interfaces.pdu_switch.turn_on(delay=100)
                # wifi_access_point.interfaces.wifi.start_ap()
                # time.sleep(100)
                ap_power_off = 0
                logger().info("Successfully powered on AP")
                logger().info("Pinging to DUT to check rejoin process is completed or not")
                status = sl_collections.ping(dut_ip, 30, 5)
                assert status, "Pinging to DUT is failed, DUT not rejoined to AP"
            logger().info(f"DUT publishes message over mqtt topic --> {topic}")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=1, timeout=20)
            time.sleep(5)
            # turning off AP after sending 4 mqtt messages from DUT
            if send_count == 4:
                ap_power_off = 1

        time.sleep(2)
        logger().info("MQTT client unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted"
            f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename)
        assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if
                "Client Key Exchange" in ssl_pkt), "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if
                "Encrypted Handshake Message" in ssl_pkt), "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if
                "Change Cipher Spec" in ssl_pkt), "Unable to find 'Change Cipher Spec' message"
        logger().info(f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), "Unable to find FIN ACK "
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {

        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}}
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_mqtt_qos0_connect_publish_rejoin_TC127758(switch, wifi_sniffer, sniffer_filter, mqtt_client, request,
                                                            wifi_access_point, mqtt_server, wifi_dut, sl_collections):
    """
    QOS0: Subscribe to MQTT server with TCP connection and publish data. check rejoin functionality after
    disconnecting from AP
    """

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=800))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        dut_ip = wifi_obj.dut_addr['device_ip']
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=0)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=0)
        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=0)
        time.sleep(3)

        ap_power_off = 0
        # Sending 5 mqtt messages before and after turning off AP
        for send_count in range(1, 11):
            if ap_power_off:
                logger().info("Turning off the AP")
                switch.interfaces.pdu_switch.turn_off(delay=20)
                # wifi_access_point.interfaces.wifi.stop_ap()
                # time.sleep(20)
                logger().info("Successfully powered off AP")

                logger().info("Again turning on the AP")
                switch.interfaces.pdu_switch.turn_on(delay=100)
                # wifi_access_point.interfaces.wifi.start_ap()
                # time.sleep(100)
                ap_power_off = 0
                logger().info("Successfully powered on AP")
                logger().info("Pinging to DUT to check rejoin process is completed or not")
                status = sl_collections.ping(dut_ip, 30, 5)
                assert status, "Pinging to DUT is failed, DUT not rejoined to AP"
            logger().info(f"DUT publishes message over the topic --> {topic}")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=1, timeout=20)
            time.sleep(5)
            # turning off AP after sending 5 mqtt messages from DUT
            if send_count == 5:
                ap_power_off = 1
        time.sleep(2)
        logger().info("Unsubscribe from the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


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
def test_wifi_sdk_mqtt_command_type_response_check_C37583(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """Command Type Response for MQTT Client Functionality"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client")
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        wifi_obj.subscribe_and_publish(qos=Si91xMqttQos.QOS0)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS0, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
        logger().info(".....Disconnect MQTT Broker........")
        wifi_dut.interfaces.mqtt.mqtt_client_disconnect()

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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 6})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_username_topic_length_check_C206125(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """Check if both the MQTT username and topic length take 100 and 120 bytes or not"""

    try:
        topic = ''.join(random.choices(string.ascii_uppercase + string.digits, k=120))
        username = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
        logger().info(f"<<<<<<<< Username is : {username} >>>>>>>>>>>>")
        logger().info(f"<<<<<<<< Topic is {topic} >>>>>>>>>>>>>>>>>>>>")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", server_port=8883,
                                                                        is_connection_encrypted=True)
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt,
                                                               send_credentials=True, username=username)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("==== MQTT Client & DUT subscribes to the topic =====")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS0)
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=Si91xMqttQos.QOS0)
        logger().info("===== DUT publishes message over the topic ======")
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS0)
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[
                   0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message " \
                                                   "received is wrong"
        assert msgs[0].qos == Si91xMqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"

        logger().info("====== MQTT client unsubscribes to the topic =======")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(2)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.verify_ps_validation()

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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_check_error_0x21_C206117(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, sniffer_filter, request, sl_collections, mqtt_client):
    """If the MQTT username is given more than 120 bytes 0x21 error code should be seen."""
    try:
        username = ''.join(random.choices(string.ascii_uppercase + string.digits, k=123))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        logger().info(f"<<<<<<<< Username is : {username} >>>>>>>>>>>>")
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                        is_connection_encrypted=True)

        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
            server=mqtt_server.interfaces.mqtt, send_credentials=True, username=username,
            expected_status=SLStatus.SL_STATUS_INVALID_PARAMETER)

        logger().info("DUT sent 0x21 when the username is more than 120 bytes")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

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
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_subscribe_wild_char_TC498668(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """Verify DUT functionality with MQTT subscription using Multi level wild card character(#) in the topic name"""

    try:
        topic_wild = "mytesttopic/#"
        multiple_topic = ["mytesttopic/sensor", "mytesttopic/automation", "mytesttopic/siliconlabs"]
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild, qos=1)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild, qos=1)

        time.sleep(3)
        count = 0
        logger().info("************** DUT publishes message over the multiple topics *******************")
        for length in multiple_topic:
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=length, message=message, qos=1, timeout=20)

            time.sleep(2)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

            assert msgs[count].topic == multiple_topic[count], "No message received by mqtt-client on subscribed topic1"
            assert msgs[count].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
            assert msgs[
                       count].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                           "message received is wrong"
            count += 1

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic_wild)
        time.sleep(1)
        wifi_obj.verify_ps_validation()
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
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_subscribe_wild_char_TC498667(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """Verify DUT functionality with MQTT subscription using Single level wild card character(+) in the topic name"""

    try:
        topic_wild = "mytesttopic/+/mytesttopic"
        multiple_topic = ["mytesttopic/sensor/mytesttopic", "mytesttopic/automation/mytesttopic",
                          "mytesttopic/siliconlabs/mytesttopic"]

        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild, qos=1)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild, qos=1)
        time.sleep(3)

        count = 0
        logger().info("**************** DUT publishes message over multiple topics *****************")
        for length in multiple_topic:
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=length, message=message, qos=1, timeout=20)
            time.sleep(2)
            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

            assert msgs[count].topic == multiple_topic[count], "No message received by mqtt-client on subscribed topic1"
            assert msgs[count].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
            assert msgs[
                       count].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                           "message received is wrong"
            count += 1

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic_wild)
        time.sleep(1)
        wifi_obj.verify_ps_validation()
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_topic_diff_length_C206126(
        wifi_sniffer, mqtt_server, mqtt_client, request, wifi_access_point, wifi_dut, sl_collections, sniffer_filter):
    """Check if the MQTT topic length is taking 100, 120 & 200 bytes"""

    try:
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            sniffer_filter=sniffer_filter, wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server,
                            mqtt_client=mqtt_client, sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        client_devices = [wifi_dut, mqtt_client]
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        for device in client_devices:
            device.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        topic_length = [100, 120, 200]

        for length in topic_length:
            logger().info(f" Subscribe topic for length : {length} bytes")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            topic = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            logger().info("**************** DUT subscribes to the topic ****************")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

            time.sleep(2)

            logger().info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1,
                                                         timeout=20)
            time.sleep(2)
            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) == 1:
                    break
            assert len(msgs) == 1, "No message is received by mqtt-client"
            assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[
                       0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                       "message received is wrong"
            assert msgs[
                       0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS0"
            time.sleep(1)
            logger().info("MQTT client unsubscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.verify_ps_validation()
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_mqtt_topic_diff_length_with_1000bytes_C465837(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """QOS1: Subscribe to MQTT server connection with different topic lengths(62, 100,122,201) and and publish maximum
    data of 1000 bytes over subscribed topic and check the DUT behavior"""

    try:
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        topic_length = [62, 100, 122, 201]
        for length in topic_length:
            topic = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))
            mqtt_client.interfaces.mqtt.received_messages.clear()
            logger().info(f" Topic Length : {length} bytes")
            logger().info("**************** DUT subscribes to the topic ****************")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

            time.sleep(3)

            logger().info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1,
                                                         timeout=20)
            time.sleep(3)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) == 1:
                    break
            assert len(msgs) == 1, "No message is received by mqtt-client"
            assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                        "message received is wrong"
            assert msgs[0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"
            logger().info("DUT unsubscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
            time.sleep(2)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.verify_ps_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_mqtt_ssl_topic_diff_length_with_diff_bytes_C463958(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """QOS1: Subscribe to MQTT server with SSL connection with different topic lengths(62,100,122,201) and publish
    data of 1000 bytes over subscribed topic and check the DUT behavior"""

    try:
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                            server_port=8883, qos=1,
                                                                            is_connection_encrypted=True)
            logger().info("Both DUT and third-party mqtt client connects to MQTT server")
            wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(25)
            mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(5)
            topic_length = [62, 100, 122, 201]
            message_length = [1, 10, 100, 512, 1000]
            for length in topic_length:
                topic = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

                mqtt_client.interfaces.mqtt.received_messages.clear()
                logger().info(f" Topic Length : {length} bytes")
                logger().info("**************** DUT subscribes to the topic ****************")
                mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
                wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

                time.sleep(3)
                count = 0
                for msg_length in message_length:
                    message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=msg_length))
                    logger().info("DUT publishes message over the topic")
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1,
                                                                 timeout=20)
                    time.sleep(3)
                    sw = Stopwatch()
                    while sw.elapsed_sec < 5:
                        time.sleep(0.1)
                        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

                        assert msgs[count].topic == topic, "No message received by mqtt-client on subscribed topic"
                        assert msgs[count].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
                        assert msgs[
                                   count].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                                       "message received is wrong"
                    count += 1
                logger().info("DUT unsubscribes to the topic")
                wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
                time.sleep(2)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted"
            f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename)
        assert (message for message in ssl_pkt if
                "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if
                "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
            "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt), \
            "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
            "Unable to find 'Change Cipher Spec' message"
        logger().info(f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), \
            "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), \
            "Unable to find FIN ACK "
        wifi_obj.verify_ps_validation()
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_mqtt_reconn_when_fails_for_first_time_C519516(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS1:Check MQTT reconnection happening or not when MQTT connection fails for the first time"""

    try:
        capture_filename = request.node.name
        topic = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1,
                                                                        server_port=1885)
        logger().info("DUT connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info("Disconnecting from MQTT Server")
        wifi_dut.interfaces.wifi.mqtt_client_deinit()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info("DUT connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("**************** DUT subscribes to the topic ****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        time.sleep(3)

        logger().info("DUT publishes message over the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1,
                                                     timeout=20)
        time.sleep(3)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"
        logger().info("DUT unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(2)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_mqtt_reconn_ssl_when_fails_for_first_time_C525358(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS1:Check MQTT_SSL reconnection happening or not when MQTT_SSL connection fails for the first time"""

    try:
        capture_filename = request.node.name
        topic = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", server_port=8885,
                                                                        qos=1, is_connection_encrypted=True)
        logger().info("DUT connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info("Disconnecting from MQTT Server")
        wifi_dut.interfaces.wifi.mqtt_client_deinit()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", server_port=8883,
                                                                        qos=1, is_connection_encrypted=True)
        logger().info("DUT connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("**************** DUT subscribes to the topic ****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        time.sleep(3)

        logger().info("DUT publishes message over the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1,
                                                     timeout=20)
        time.sleep(3)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"
        logger().info("DUT unsubscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(2)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_mqtt_with_qos_last_will_and_retained_will_to_zero_C537960(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """Verify whether DUT is able to connect to MQTT server or when QOS_OF_LAST_WILL & IS_LAST_WILL_RETAINED set 0"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", qos=0, is_retained=False, will_message="")

        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)

        logger().info("*************** MQTT Client subscribes to the topic *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=0)
        logger().info("*************** DUT subscribes to the topic1 *******************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=0)
        time.sleep(5)

        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            logger().info("*************** DUT publishes message over the topic *****************")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=0, timeout=20)
            time.sleep(5)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS0, "DUT sent message with wrong QOS. expected is QOS0"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"

        time.sleep(2)

        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_qos0_mqtt_ssl_with_two_topic_length_C537950(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """QOS0:Verify whether DUT is able to subscribe 2 topics with 2 different lengths and check the DUT behavior and
    also check whether it is able to receive data on both subscribed topics(Try with different lengths) over MQTT SSL"""

    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        topic2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", server_port=8883, is_connection_encrypted=True)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        logger().info("*************** DUT subscribes to the topic1 *******************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic2 ***************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=0)
        logger().info("*************** DUT subscribes to the topic2 ***************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=0)
        time.sleep(5)

        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            logger().info("MQTT Client publishes message over the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic1, payload=message, qos=0)
            time.sleep(5)

            logger().info("MQTT Client publishes message over the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic2, payload=message, qos=0)
            time.sleep(5)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()

        assert msgs[0] == topic1, "No message received by DUT on subscribed topic"
        assert msgs[1] == message, "No message is received by DUT on subscribed topic or " \
                                   "message received is wrong"
        time.sleep(2)

        msgss = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgss = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()

        assert msgss[2] == topic2, "No message received by DUT on subscribed topic"
        assert msgss[3] == message, "No message is received by DUT on subscribed topic or " \
                                    "message received is wrong"

        logger().info("....Unsubscribing from the topic1....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic1)

        logger().info("....Unsubscribing from the topic2....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_qos1_mqtt_ssl_with_two_topic_length_C537951(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """QOS1:Verify whether DUT is able to subscribe 2 topics with 2 different lengths and check the DUT behavior and
    also check whether it is able to receive data on both subscribed topics(Try with different lengths) over MQTT SSL"""

    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=120))
        topic2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", server_port=8883, is_connection_encrypted=True, qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
        logger().info("*************** DUT subscribes to the topic1 *******************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic2 ***************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
        logger().info("*************** DUT subscribes to the topic2 ***************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
        time.sleep(5)

        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            logger().info("MQTT Client publishes message over the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic1, payload=message, qos=1)
            time.sleep(5)

            logger().info("MQTT Client publishes message over the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic2, payload=message, qos=1)
            time.sleep(5)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()

        assert msgs[0] == topic1, "No message received by DUT on subscribed topic"
        assert msgs[1] == message, "No message is received by DUT on subscribed topic or " \
                                   "message received is wrong"
        time.sleep(2)

        msgss = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgss = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()

        assert msgss[2] == topic2, "No message received by DUT on subscribed topic"
        assert msgss[3] == message, "No message is received by DUT on subscribed topic or " \
                                    "message received is wrong"

        logger().info("....Unsubscribing from the topic1....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic1)

        logger().info("....Unsubscribing from the topic2....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_qos0_mqtt_with_two_topic_length_C537958(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """QOS0:Verify whether DUT is able to publish 2 different topics over MQTT"""

    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=70))
        topic2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=80))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        mqtt_tx_obj = mqtt_publish_message_tx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1, topic2=topic2,
                                              message=message, qos=0, utf_constants=utf_constants)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client")
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        logger().info("*************** DUT subscribes to the topic1 *******************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic2 ***************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=0)
        logger().info("*************** DUT subscribes to the topic2 ***************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=0)
        time.sleep(5)

        mqtt_tx_obj.start()
        mqtt_tx_obj.wait_for_exit()

        logger().info("....Unsubscribing from the topic1....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic1)

        logger().info("....Unsubscribing from the topic2....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_qos0_mqtt_simultaneous_with_two_topic_length_C537952(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """QOS0:Verify whether DUT is able to do simultaneous publish and subscribe from 2 different topics with MQTT
    (Try with different topic lengths)"""

    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        topic2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        mqtt_rx_obj = mqtt_publish_message_rx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1, topic2=topic2,
                                              message=message, qos=0, utf_constants=utf_constants)

        mqtt_tx_obj = mqtt_publish_message_tx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1, topic2=topic2,
                                              message=message, qos=0, utf_constants=utf_constants)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=0)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic1 *******************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic2 ***************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=0)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic2 ***************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=0)
        time.sleep(5)

        mqtt_rx_obj.start()
        mqtt_tx_obj.start()
        mqtt_tx_obj.wait_for_exit()
        mqtt_rx_obj.wait_for_exit()
        time.sleep(5)
        mqtt_rx_obj.dut_receive_check()

        logger().info("....Unsubscribing from the topic1....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic1)

        logger().info("....Unsubscribing from the topic2....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_qos0_mqtt_ssl_simultaneous_with_two_topic_length_C537955(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """QOS0:Verify whether DUT is able to do simultaneous publish and subscribe from 2 different topics with MQTT
    over SSL(Try with different topic lengths)"""

    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        topic2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        mqtt_rx_obj = mqtt_publish_message_rx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1, topic2=topic2,
                                              message=message, qos=0, utf_constants=utf_constants)

        mqtt_tx_obj = mqtt_publish_message_tx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1, topic2=topic2,
                                              message=message, qos=0, utf_constants=utf_constants)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=0,
                                                                        server_port=8883, is_connection_encrypted=True)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic1 *******************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic2 ***************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=0)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic2 ***************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=0)
        time.sleep(5)

        mqtt_rx_obj.start()
        mqtt_tx_obj.start()
        mqtt_tx_obj.wait_for_exit()
        mqtt_rx_obj.wait_for_exit()
        time.sleep(5)
        mqtt_rx_obj.dut_receive_check()

        logger().info("....Unsubscribing from the topic1....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic1)

        logger().info("....Unsubscribing from the topic2....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_qos1_mqtt_ssl_simultaneous_with_two_topic_length_C537953(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """QOS1:Verify whether DUT is able to do simultaneous publish and subscribe from 2 different topics with MQTT over
    SSL(Try with different topic lengths)"""

    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        topic2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        mqtt_rx_obj = mqtt_publish_message_rx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1, topic2=topic2,
                                              message=message, qos=1, utf_constants=utf_constants)

        mqtt_tx_obj = mqtt_publish_message_tx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1, topic2=topic2,
                                              message=message, qos=1, utf_constants=utf_constants)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        for count in range(0, 3):
            wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
                server_port=8883, is_connection_encrypted=True, client_id="Si91x_mqtt_client", qos=1)
            logger().info(".....DUT connects to MQTT server.....")
            wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(25)
            logger().info(".....MQTT Client connects to MQTT server.....")
            mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(5)

            logger().info("*************** MQTT Client subscribes to the topic1 *****************")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
            time.sleep(2)
            logger().info("*************** DUT subscribes to the topic1 *******************")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
            time.sleep(5)

            logger().info("*************** MQTT Client subscribes to the topic2 ***************")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
            time.sleep(2)
            logger().info("*************** DUT subscribes to the topic2 ***************")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
            time.sleep(5)

            mqtt_rx_obj.start()
            mqtt_tx_obj.start()
            mqtt_tx_obj.wait_for_exit()
            mqtt_rx_obj.wait_for_exit()
            time.sleep(5)
            mqtt_rx_obj.dut_receive_check()

            logger().info("....Unsubscribing from the topic1....")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic1)
            time.sleep(5)

            logger().info("....Unsubscribing from the topic2....")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2)
            time.sleep(5)

            logger().info("....disconnecting from MQTT broker....")
            wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
            time.sleep(5)

            logger().info("....calling de-init API....")
            wifi_dut.interfaces.mqtt.mqtt_client_deinit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_qos1_mqtt_simultaneous_with_two_topic_length_C537954(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """QOS1:Verify whether DUT is able to do simultaneous publish and subscribe from 2 different topics with MQTT
    (Try with different topic lengths)"""

    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        topic2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        mqtt_rx_obj = mqtt_publish_message_rx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1, topic2=topic2,
                                              message=message, qos=1, utf_constants=utf_constants)

        mqtt_tx_obj = mqtt_publish_message_tx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1, topic2=topic2,
                                              message=message, qos=1, utf_constants=utf_constants)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic1 *******************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic2 ***************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic2 ***************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
        time.sleep(5)

        mqtt_rx_obj.start()
        mqtt_tx_obj.start()
        mqtt_tx_obj.wait_for_exit()
        mqtt_rx_obj.wait_for_exit()
        time.sleep(5)
        mqtt_rx_obj.dut_receive_check()

        logger().info("....Unsubscribing from the topic1....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic1)

        logger().info("....Unsubscribing from the topic2....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.config("raspi_mosquitto_auth",
                    mqtt=[{"username": "mytesttopic",
                           "password": "axvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjca"}])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_mqtt_password_more_than_61_bytes_C463963(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):

    """QOS1: If password length is given more than 61 bytes error code should be seen"""

    try:
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        username = "mytesttopic"
        password = "axvvejvuhtqpwxpudnhvqeypfqtvqmwztcgbxwidtynrmypnhfkjdguyeppgjca"
        logger().info(f"************* Username Length : {username} bytes *************")

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", qos=1)

        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
            server=mqtt_server.interfaces.mqtt, send_credentials=True, username=username, password=password,
            expected_status=SLStatus.SL_STATUS_INVALID_PARAMETER)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("************ Stop the sniffer **************")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_mqtt_client_id_more_than_61_bytes_C463961(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """QOS1:  If client id length is given more than 61 bytes error code 0x21 should be seen"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        client_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=63))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id=client_id, qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt,
                                                               expected_status=SLStatus.SL_STATUS_INVALID_PARAMETER)
        time.sleep(10)

        logger().info("******* client id length is more than 61 bytes so error code 0x0021 should be seen ********")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_dut_hit_mqtt_disconnect_handler_C537967(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """Verify whether DUT is able to hit the mqtt disconnect event handler or not when we close the MQTT broker"""

    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        topic2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.
                                                            channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        (wifi_dut.interfaces.wifi.wifi_set_advanced_client_config
         (max_retry_attempts=0, scan_interval=4, beacon_missed_count=40, first_time_retry_enable=0))

        sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated)

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=0)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic1 *******************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic2 ***************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=0)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic2 ***************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=0)
        time.sleep(5)

        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            logger().info("********* MQTT Client publishes message over the topic1 **********")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic1, payload=message, qos=0)
            time.sleep(1)

            logger().info("********* MQTT Client publishes message over the topic2 *********")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic2, payload=message, qos=0)
            time.sleep(1)

        logger().info('***** Closing MQTT Broker *****')
        mqtt_server.interfaces.mqtt.stop_server()
        time.sleep(10)

        event_data_output = ""
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.MQTT_DISCONNECT_EVENT:
                event_data_output = event.event_data

        logger().info(f" ***************** EVENT DATA IS : {event_data_output} ********************** ")

        assert "SL_MQTT_CLIENT_DISCONNECTED_EVENT" in event_data_output, "expected event not found in event data"

        logger().info(f" ********* DUT HIT THE MQTT DISCONNECT EVENT : SL_MQTT_CLIENT_DISCONNECTED_EVENT *********** ")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_qos0_mqtt_two_topic_and_three_condition_C498669(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """Verify whether DUT is able to subscribe 2 topics with 2 different lengths and check the DUT behavior and
    check whether it is able to receive data on both subscribed topics"""

    try:
        topic1 = ["mytestmytest", "mytestmytestmytestmytest", "mytestmytestmytestmytestmytestmytest"]
        topic2 = ["mytestmytestmytestmytestmytestmytest", "mytestmytestmytestmytest", "mytestmytest"]
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        mqtt_rx_obj = mqtt_publish_message_rx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1, topic2=topic2,
                                              message=message, qos=1, utf_constants=utf_constants)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        for i in range(len(topic1)):
            wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client")
            logger().info(".....DUT connects to MQTT server.....")
            wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(25)
            logger().info(".....MQTT Client connects to MQTT server.....")
            mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(5)

            logger().info("*************** MQTT Client subscribes to the topic1 *****************")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1[i], qos=0)
            logger().info("*************** DUT subscribes to the topic1 *******************")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1[i], qos=0)
            time.sleep(5)

            logger().info("*************** MQTT Client subscribes to the topic2 ***************")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2[i], qos=0)
            logger().info("*************** DUT subscribes to the topic2 ***************")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2[i], qos=0)
            time.sleep(5)

            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):
                logger().info("********* MQTT Client publishes message over the topic1 **********")
                mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic1[i], payload=message,
                                                                qos=0)
                time.sleep(2)

                logger().info("********* MQTT Client publishes message over the topic2 *********")
                mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic2[i], payload=message,
                                                                qos=0)
                time.sleep(2)

            mqtt_rx_obj.dut_receive_check()

            logger().info("....Unsubscribing from the topic1....")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic1[i])

            logger().info("....Unsubscribing from the topic2....")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2[i])

            logger().info("....Disconnecting from MQTT Server....")
            wifi_dut.interfaces.wifi.mqtt_client_disconnect()
            time.sleep(3)

            mqtt_client.interfaces.mqtt.mqtt_client_close()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.config("raspi_mosquitto_tls", mqtt={"accounts": [{
                                                                  "username": "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyuse",
                                                                  "password": "FROM_TEST_1"},
                                                              {
                                                                  "username": "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewit",
                                                                  "password": "FROM_TEST_2"},
                                                              {
                                                                  "username": "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyus",
                                                                  "password": "FROM_TEST_3"}]})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_mqtt_ssl_username_diff_length_with_diff_bytes_C463960(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """QOS1: Subscribe to MQTT server with SSL connection with different Username lengths(62,100,121)
    and publish data over subscribed topic and check the DUT behavior"""

    try:
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):

            wifi_obj.start()
            wifi_obj.wait_for_exit()

            username_length = [
                "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyuse",
                "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewit",
                "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyus"]

            password = ["FROM_TEST_1", "FROM_TEST_2", "FROM_TEST_3"]
            message_length = [1, 10, 100, 512, 1000]
            topic = 'mytesttopic'
            qos = 1
            for length in range(len(username_length)):

                wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

                wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
                    server_port=8883, is_connection_encrypted=True, client_id="Si91x_mqtt_client", qos=1)

                logger().info("Both DUT and third-party mqtt client connects to MQTT server")
                wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
                    server=mqtt_server.interfaces.mqtt, send_credentials=True, username=username_length[length],
                    password=password[length])
                time.sleep(25)
                mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
                time.sleep(5)

                logger().info("**************** DUT subscribes to the topic ****************")
                mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
                wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

                time.sleep(3)
                count = 0
                for msg_length in message_length:
                    message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=msg_length))
                    logger().info("********** DUT publishes message over the topic ****************")
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1,
                                                                 timeout=20)
                    time.sleep(5)

                    sw = Stopwatch()
                    while sw.elapsed_sec < 20:
                        found = False
                        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                        if topic and message and qos in msgs:
                            if found:
                                break
                            assert found, "topic or message or qos not found"
                    count += 1

                logger().info("************ DUT unsubscribes to the topic ******************")
                wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
                time.sleep(5)

                logger().info("************ Disconnecting from MQTT Server ******************")
                wifi_dut.interfaces.wifi.mqtt_client_disconnect()
                time.sleep(5)

            logger().info("************ Stop the sniffer **************")
            wifi_sniffer.interfaces.capture.stop_capture()

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info(
            f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted"
            f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(decryption_key, wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename)
        assert (message for message in ssl_pkt if
                "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if
                "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
            "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt), \
            "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
            "Unable to find 'Change Cipher Spec' message"
        logger().info(f"===== TCP Packet decryption and check SYN, FIN, ACK, FIN ACK ======")
        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in tcp_pkt), "Unable to find SYN packet"
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in tcp_pkt), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in tcp_pkt), \
            "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in tcp_pkt), \
            "Unable to find FIN ACK "

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.config("raspi_mosquitto_auth", mqtt={"accounts": [{
                                                                   "username": "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyuse",
                                                                   "password": "FROM_TEST_1"},
                                                               {
                                                                   "username": "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewit",
                                                                   "password": "FROM_TEST_2"},
                                                               {
                                                                   "username": "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyus",
                                                                   "password": "FROM_TEST_3"}]})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_mqtt_username_diff_length_with_diff_bytes_C465838(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """QOS1: Subscribe to MQTT server connection with different Username lengths(62,100,121) and publish data bytes
    over subscribed topic and check the DUT behavior"""

    try:
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):

            wifi_obj.start()
            wifi_obj.wait_for_exit()

            username_length = [
                "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyuse",
                "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewit",
                "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyus"]

            password = ["FROM_TEST_1", "FROM_TEST_2", "FROM_TEST_3"]
            message_length = [1, 10, 100, 512, 1000]
            topic = 'mytesttopic'
            qos = 1
            for length in range(len(username_length)):

                wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

                wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)

                logger().info("Both DUT and third-party mqtt client connects to MQTT server")
                wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
                    server=mqtt_server.interfaces.mqtt, send_credentials=True, username=username_length[length],
                    password=password[length])
                time.sleep(25)
                mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
                time.sleep(5)

                logger().info("**************** DUT subscribes to the topic ****************")
                mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
                wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

                time.sleep(3)
                count = 0
                for msg_length in message_length:
                    message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=msg_length))
                    logger().info("********** DUT publishes message over the topic ****************")
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1,
                                                                 timeout=20)
                    time.sleep(5)

                    sw = Stopwatch()
                    while sw.elapsed_sec < 20:
                        found = False
                        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                        if topic and message and qos in msgs:
                            if found:
                                break
                            assert found, "topic or message or qos not found"

                    count += 1

                logger().info("************ DUT unsubscribes to the topic ******************")
                wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
                time.sleep(5)

                logger().info("************ Disconnecting from MQTT Server ******************")
                wifi_dut.interfaces.wifi.mqtt_client_disconnect()
                time.sleep(5)
                mqtt_client.interfaces.mqtt.mqtt_client_close()
            logger().info("************ Stop the sniffer **************")
            wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}}
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_qos0_two_topic_with_SSL_connection_rejoin_c537956(
        switch, wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections,
        sniffer_filter):
    """QOS0:check whether DUT is able to reconnect MQTT and subscribe with 2 topics and publish after rejoin failed MQTT
    over SSL"""
    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        topic2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, message=message, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        dut_ip = wifi_obj.dut_addr['device_ip']
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                        server_port=8883, qos=0,
                                                                        is_connection_encrypted=True)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        mqtt_client.interfaces.mqtt.received_messages.clear()
        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic1 *******************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic2 ***************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=0)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic2 ***************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=0)
        time.sleep(5)

        ap_power_off = 0
        # Sending 10 mqtt messages before and after turning off AP
        for send_count in range(1, 21):
            if ap_power_off:
                logger().info("Turning off the AP")
                switch.interfaces.pdu_switch.turn_off(delay=20)

                logger().info("Successfully powered off AP")

                logger().info("Again turning on the AP")
                switch.interfaces.pdu_switch.turn_on(delay=100)

                ap_power_off = 0
                logger().info("Successfully powered on AP")
                logger().info("Pinging to DUT to check rejoin process is completed or not")
                status = sl_collections.ping(dut_ip, 30, 5)
                assert status, "Pinging to DUT is failed, DUT not rejoined to AP"
            logger().info("********* DUT publishes message over the topic1 *********")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic1, message=message, qos=0, timeout=20)
            time.sleep(5)

            logger().info("********* DUT publishes message over the topic2 *********")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic2, message=message, qos=0, timeout=20)
            time.sleep(5)

            logger().info("********* MQTT Client publishes message over the topic1 **********")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic1, payload=message, qos=0)
            time.sleep(2)

            logger().info("********* MQTT Client publishes message over the topic2 *********")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic2, payload=message, qos=0)
            time.sleep(2)
            # turning off AP after sending 10 mqtt messages from DUT
            if send_count == 10:
                ap_power_off = 1

        time.sleep(2)

        logger().info("....Unsubscribing from the topic1....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic1)
        time.sleep(3)
        logger().info("....Unsubscribing from the topic2....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2)
        time.sleep(3)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}}
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_qos1_two_topic_with_SSL_connection_rejoin_c537959(
        switch, wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections,
        sniffer_filter):
    """QOS1:Verify whether DUT is able to publish 2 different topics over MQTT after rejoin failed"""
    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=70))
        topic2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=80))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, message=message, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        dut_ip = wifi_obj.dut_addr['device_ip']
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                        server_port=8883, qos=1,
                                                                        is_connection_encrypted=True)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        mqtt_client.interfaces.mqtt.received_messages.clear()
        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic1 *******************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic2 ***************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic2 ***************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
        time.sleep(5)

        ap_power_off = 0
        # Sending 15 mqtt messages before and after turning off AP
        for send_count in range(1, 31):
            if ap_power_off:
                logger().info("Turning off the AP")
                switch.interfaces.pdu_switch.turn_off(delay=20)

                logger().info("Successfully powered off AP")

                logger().info("Again turning on the AP")
                switch.interfaces.pdu_switch.turn_on(delay=100)

                ap_power_off = 0
                logger().info("Successfully powered on AP")
                logger().info("Pinging to DUT to check rejoin process is completed or not")
                status = sl_collections.ping(dut_ip, 30, 5)
                assert status, "Pinging to DUT is failed, DUT not rejoined to AP"
            logger().info("********* DUT publishes message over the topic1 *********")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic1, message=message, qos=1, timeout=20)
            time.sleep(5)

            logger().info("********* DUT publishes message over the topic2 *********")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic2, message=message, qos=1, timeout=20)
            time.sleep(5)

            # turning off AP after sending 15 mqtt messages from DUT
            if send_count == 15:
                ap_power_off = 1

        time.sleep(2)

        logger().info("....Unsubscribing from the topic1....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic1)
        time.sleep(3)
        logger().info("....Unsubscribing from the topic2....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2)
        time.sleep(3)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}}
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_qos1_two_topic_with_SSL_connection_rejoin_failed_c537957(
        switch, wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections,
        sniffer_filter):
    """QOS1:check whether DUT is able to reconnect MQTT and subscribe with 2 topics and publish after rejoin process
    MQTT over SSL(DUT has to hit the MQTT disconnect event handler)

"""
    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        topic2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, message=message, sniffer_filter=sniffer_filter)

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.
                                                            channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        (wifi_dut.interfaces.wifi.wifi_set_advanced_client_config
         (max_retry_attempts=5, scan_interval=4, beacon_missed_count=40, first_time_retry_enable=0))

        sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, associated=wifi_dut.interfaces.wifi.associated)

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", server_port=8883, qos=1, is_connection_encrypted=True)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        with TimeMeasurer() as t:
            wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(20)
        logger().info(f"mqtt connection time duration {t.duration} seconds")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        mqtt_client.interfaces.mqtt.received_messages.clear()
        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic1 *******************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic2 ***************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic2 ***************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
        time.sleep(5)

        for count in range(1, 11):
            logger().info("********* DUT publishes message over the topic1 *********")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic1, message=message, qos=1, timeout=20)
            time.sleep(5)

            logger().info("********* DUT publishes message over the topic2 *********")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic2, message=message, qos=1, timeout=20)
            time.sleep(5)

            logger().info("********* MQTT Client publishes message over the topic1 **********")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic1, payload=message, qos=1)
            time.sleep(2)

            logger().info("********* MQTT Client publishes message over the topic2 *********")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic2, payload=message, qos=1)
            time.sleep(2)

        logger().info("Turning off the AP")
        switch.interfaces.pdu_switch.turn_off(delay=20)

        logger().info("Successfully powered off AP")
        time.sleep(60)
        wifi_obj.rejoin_async_event()
        logger().info("Again turning on the AP")
        switch.interfaces.pdu_switch.turn_on(delay=100)

        sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, associated=False)

        time.sleep(2)

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", server_port=8883, qos=1, is_connection_encrypted=True)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        with TimeMeasurer() as t1:
            logger().info("Both DUT and third-party mqtt client connects to MQTT server")
            wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(20)
        logger().info(f"mqtt connection after rejoin time duration {t1.duration} seconds")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        mqtt_client.interfaces.mqtt.received_messages.clear()
        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic1 *******************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic2 ***************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
        time.sleep(2)
        logger().info("*************** DUT subscribes to the topic2 ***************")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
        time.sleep(5)

        for count in range(1, 11):
            logger().info("********* DUT publishes message over the topic1 *********")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic1, message=message, qos=1, timeout=20)
            time.sleep(5)

            logger().info("********* DUT publishes message over the topic2 *********")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic2, message=message, qos=1, timeout=20)
            time.sleep(5)

            logger().info("********* MQTT Client publishes message over the topic1 **********")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic1, payload=message, qos=1)
            time.sleep(2)

            logger().info("********* MQTT Client publishes message over the topic2 *********")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic2, payload=message, qos=1)
            time.sleep(2)

        logger().info("....Unsubscribing from the topic1....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic1)
        time.sleep(3)
        logger().info("....Unsubscribing from the topic2....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2)
        time.sleep(3)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        mqtt_connection = 0
        if t1.duration < t.duration:
            logger().info(
                " after rejoin mqtt connection time is less than 1st time mqtt connection time . which is expected")
            mqtt_connection = 1
            assert mqtt_connection, f"after rejoin mqtt connection time is more than 1st time mqtt connection time . which is not expected"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_wild_char_one_topic_with_single_multiple_c537972(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """Verify DUT functionality with MQTT subscription topic used combination of single level(+) and multilevel
    wild card(#) characters and receive the data on subscribed topic using emb_mqtt"""

    try:
        topic_wild = "patch/+/properties/desired/#"
        multiple_topic = ["patch/iothub/properties/desired/sensor", "patch/substation/properties/desired/automation",
                          "patch/workspace/properties/desired/siliconlabs"]
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", server_port=8883, qos=1, is_connection_encrypted=True)

        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild, qos=1)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild, qos=1)
        time.sleep(3)

        logger().info("************** DUT publishes message over the multiple topics *******************")
        for _ in range(10):
            for length in multiple_topic:
                mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=length, payload=message, qos=1)
                time.sleep(2)

                wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()

        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic_wild)
        time.sleep(3)

        logger().info("....disconnecting from MQTT broker....")
        wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
        time.sleep(3)

        logger().info("....calling MQTT de-init API....")
        wifi_dut.interfaces.mqtt.mqtt_client_deinit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_wild_char_two_topic_single_and_multiple_c537973(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """Verify whether DUT is able to subscribe 2 topics with single and multi level wild card and receive the data on
    subscribed topic using emb_mqtt"""

    try:
        topic_wild_first = "mytesttopic/#"
        multiple_topic_first = ["mytesttopic/sensor", "mytesttopic/automation", "mytesttopic/siliconlabs"]

        topic_wild_second = "mytesttopic/+/mytesttopic"
        multiple_topic_second = ["mytesttopic/sensor/mytesttopic", "mytesttopic/automation/mytesttopic",
                                 "mytesttopic/siliconlabs/mytesttopic"]

        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", server_port=8883, qos=1, is_connection_encrypted=True)

        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic 1")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild_first, qos=1)

        logger().info("DUT subscribes to the topic 1")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild_first, qos=1)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic 2")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild_second, qos=1)

        logger().info("DUT subscribes to the topic 2")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild_second, qos=1)
        time.sleep(5)

        logger().info("************** MQTT client publishes message over the multiple topics *******************")
        for i in range(len(multiple_topic_first)):
            for count in range(0, 10):
                sw = Stopwatch()
                while sw.elapsed_sec < 10:
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=multiple_topic_first[i], payload=message,
                                                                    qos=1)
                    time.sleep(2)

                    wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()

                sw = Stopwatch()
                while sw.elapsed_sec < 10:
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=multiple_topic_second[i], payload=message,
                                                                    qos=1)
                    time.sleep(2)

                    wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()

        logger().info("....Unsubscribing from the topic 1....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic_wild_first)
        time.sleep(3)

        logger().info("....Unsubscribing from the topic 2....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic_wild_second)
        time.sleep(3)

        logger().info("....disconnecting from MQTT broker....")
        wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
        time.sleep(3)

        logger().info("....calling MQTT de-init API....")
        wifi_dut.interfaces.mqtt.mqtt_client_deinit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_wild_char_two_topic_dollar_c537977(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """Verify DUT functionality with MQTT subscription Topics beginning with $ in the topic name and receive the
    data on subscribed topic"""

    try:
        topic_wild_first = "$SYmytesttopic"

        topic_wild_second = "$SYmymqtttestplan/automation"

        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))

        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", server_port=8883, qos=1, is_connection_encrypted=True)

        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic 1")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild_first, qos=1)

        logger().info("DUT subscribes to the topic 1")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild_first, qos=1)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic 2")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild_second, qos=1)

        logger().info("DUT subscribes to the topic 2")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild_second, qos=1)
        time.sleep(5)

        logger().info("************** MQTT client publishes message over the wild topic *******************")
        for count in range(0, 10):
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic_wild_first, payload=message, qos=1)
                time.sleep(2)

                wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()

            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=topic_wild_second, payload=message, qos=1)
                time.sleep(2)

                wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()

        logger().info("....Unsubscribing from the topic 1....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic_wild_first)
        time.sleep(3)

        logger().info("....Unsubscribing from the topic 2....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic_wild_second)
        time.sleep(3)

        logger().info("....disconnecting from MQTT broker....")
        wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
        time.sleep(3)

        logger().info("....calling MQTT de-init API....")
        wifi_dut.interfaces.mqtt.mqtt_client_deinit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_qos1_wifi_init_mqtt_simultaneous_publish_subscribe_deinit_c586178(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants):
    """QOS1:Verify whether DUT is able to do simultaneous publish and subscribe from 2 different topics with MQTT over
    SSL(WIFI INIT-> WLAN Connect-> MQTT Connect -> WIFI DEINIT)"""

    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        topic2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        mqtt_rx_obj = mqtt_publish_message_rx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1, topic2=topic2,
                                              message=message, qos=1, utf_constants=utf_constants)

        mqtt_tx_obj = mqtt_publish_message_tx(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1, topic2=topic2,
                                              message=message, qos=1, utf_constants=utf_constants)

        for count in range(0, 4):
            wifi_obj.start()
            wifi_obj.wait_for_exit()

            wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
                server_port=8883, is_connection_encrypted=True, client_id="Si91x_mqtt_client", qos=1)

            logger().info(".....DUT connects to MQTT server.....")
            wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(25)
            logger().info(".....MQTT Client connects to MQTT server.....")
            mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(5)

            logger().info("*************** MQTT Client subscribes to the topic1 *****************")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
            time.sleep(2)
            logger().info("*************** DUT subscribes to the topic1 *******************")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=1)
            time.sleep(5)

            logger().info("*************** MQTT Client subscribes to the topic2 ***************")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
            time.sleep(2)
            logger().info("*************** DUT subscribes to the topic2 ***************")
            wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic2, qos=1)
            time.sleep(5)

            mqtt_rx_obj.start()
            mqtt_tx_obj.start()
            mqtt_tx_obj.wait_for_exit()
            mqtt_rx_obj.wait_for_exit()

            logger().info("....Unsubscribing from the topic1....")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic1)
            time.sleep(5)

            logger().info("....Unsubscribing from the topic2....")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic2)
            time.sleep(5)

            logger().info("....disconnecting from MQTT broker....")
            wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
            time.sleep(5)

            logger().info("....initiating leave from DUT....")
            wifi_dut.interfaces.wifi.leave()
            time.sleep(1)
            logger().info("....calling WLAN de-init API....")
            logger().info(
                "...WLAN de-init is failing used reset now ,after the fix provided can be checked with deinit ...")
            # wifi_dut.interfaces.wifi.deinit()
            logger().info("WLAN deint is not working as expected hence changing to reset")
            wifi_dut.interfaces.wifi.reset()
            time.sleep(10)

            logger().info("....calling WLAN init API....")
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            wifi_dut.interfaces.wifi.init(load_certificate=False)
            wifi_dut.interfaces.wifi.initialize_thread()
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [('0xc8', 0)])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_qos1_tcp_tx_mqtt_simultaneously_C537965(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        protocol, net_perf_client, traffic, qos, wifi_client):
    """QOS1:Verify whether DUT is able to connect to TCP and MQTT connection simultaneously in STA mode"""
    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        mqtt_funct_obj = mqttfunctionality(wifi_dut=wifi_dut, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                                           topic=topic, message=message)

        data_transfer_obj = Iperf(
            wifi_dut=wifi_dut, net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
            traffic=traffic, wifi_access_point=wifi_access_point, qos=qos, capture_filename=capture_filename,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")

        sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, associated=wifi_dut.interfaces.wifi.associated)

        data_transfer_obj.start()
        mqtt_funct_obj.start()
        mqtt_funct_obj.wait_for_exit()
        data_transfer_obj.wait_for_exit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_null_topic_C537970(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """Verify whether DUT is throwing an error or not while Subscribe/publish to MQTT server with topic name("")"""

    try:
        topic = "NULL"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)

        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(2)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=1)

        mqtt_event_data = ""
        time.sleep(7)
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.MQTT_SUBSCRIBE_FAILURE_INDICATION:
                mqtt_event_data = event.event_data

        logger().info(f"****** MQTT EVENT DATA RECEIVED : {mqtt_event_data} *******")

        content = re.findall(r"(Terminating\s\w+,\s\w+: \d+)", mqtt_event_data)
        logger().info(f"****** MQTT Subscription Failure Indication : {content} *******")

        assert "Terminating program, Error: 2" in mqtt_event_data, "expected error code not found. Expected is Error: 2"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 3, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_qos0_mqtt_ssl_http_post_simultaneously_C563985(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants, http_server, http_client, index_path):
    """QOS0:Verify whether DUT is able to connect to HTTP_POST and MQTT connection in STA mode"""
    try:

        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        capture_filename = "mqtt_ssl_http_post_C563985"

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                            wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=0,
                                                                        server_port=8883,
                                                                        is_connection_encrypted=True)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        time.sleep(5)

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

        resource_path = index_path
        logger().info(f"*** AFTER RESOURCE PTH IS  {resource_path} ****")
        http_address = wifi_dut.interfaces.wifi.allocate_memory(size=len(resource_path) + 1)
        logger().info(f"*** HTTP ADDRESS IS {http_address} ****")
        wifi_dut.interfaces.wifi.load_memory(address=http_address, size=len(resource_path), write_content=resource_path)

        if message is not None:
            message_address = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
            wifi_dut.interfaces.wifi.load_memory(address=message_address, size=len(message), write_content=message)
        if topic1 is not None:
            topic1_address = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic1) + 1)
            wifi_dut.interfaces.wifi.load_memory(address=topic1_address, size=len(topic1), write_content=topic1)

        http_post_obj = http_post(http_server=http_server, http_client=http_client, wifi_dut=wifi_dut,
                                  index_path=http_address)
        mqtt_tx_obj = mqtt_publish_message_tx_allocate_mem(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1,
                                              message=message, qos=0,
                                              message_address=message_address, topic_address=topic1_address, load_mem=True)

        logger().info("Enabling http client init process")
        wifi_dut.interfaces.wifi.http_client_init(https_enable=False)

        logger().info("*************** MQTT TX THREAD STARTED ***************")
        mqtt_tx_obj.start()
        time.sleep(1)
        logger().info("*************** HTTP POST THREAD STARTED ***************")
        http_post_obj.start()
        time.sleep(1)

        http_post_obj.wait_for_exit()
        mqtt_tx_obj.wait_for_exit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("....initiating leave from DUT....")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(1)
        logger().info("....calling WLAN Reset....")
        wifi_dut.interfaces.wifi.reset()
        time.sleep(10)
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 3, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_qos0_mqtt_ssl_http_put_simultaneously_C563986(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter,
        utf_constants, http_server, http_client, index_path):
    """Verify whether DUT is able to connect to http PUT and MQTT over SSL connection simultaneously in STA mode"""

    try:
        topic1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        capture_filename = "mqtt_ssl_http_put_C563986"

        logger().info(f"index path is {index_path}")
        logger().info(f"type of index path is {type(index_path)}")

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=0,
                                                                        server_port=8883, is_connection_encrypted=True)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("*************** MQTT Client subscribes to the topic1 *****************")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic1, qos=0)
        time.sleep(10)

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

        resource_path = index_path
        logger().info(f"*** AFTER RESOURCE PTH IS  {resource_path} ****")
        http_address = wifi_dut.interfaces.wifi.allocate_memory(size=len(resource_path) + 1)
        logger().info(f"*** HTTP ADDRESS IS {http_address} ****")
        wifi_dut.interfaces.wifi.load_memory(address=http_address, size=len(resource_path), write_content=resource_path)

        if message is not None:
            message_address = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
            wifi_dut.interfaces.wifi.load_memory(address=message_address, size=len(message), write_content=message)
        if topic1 is not None:
            topic1_address = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic1) + 1)
            wifi_dut.interfaces.wifi.load_memory(address=topic1_address, size=len(topic1), write_content=topic1)

        http_obj = http_put(http_server=http_server, http_client=http_client, wifi_dut=wifi_dut, index_path=http_address)
        mqtt_tx_obj = mqtt_publish_message_tx_allocate_mem(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic1=topic1,
                                              message=message, qos=0,
                                              message_address=message_address, topic_address=topic1_address,load_mem=True)

        logger().info("*** MQTT tx thread starting ***")
        mqtt_tx_obj.start()
        time.sleep(2)

        logger().info("*** HTTP PUT  thread starting ***")
        http_obj.start()
        time.sleep(2)

        http_obj.wait_for_exit()
        mqtt_tx_obj.wait_for_exit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        wifi_obj.verify_ps_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("....initiating leave from DUT....")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(1)
        logger().info("....calling WLAN Reset....")
        wifi_dut.interfaces.wifi.reset()
        time.sleep(10)
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_dut_null_username_password_c641389(wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point,
                                                     wifi_dut, request, sl_collections, sniffer_filter, utf_constants):
    """Negative case:Verify whether DUT is throwing an 85 error or not while connecting to MQTT server with
    empty/nothing mentioned in username and password("")"""
    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt, username="NULL",
                                                               password="NULL")
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

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
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_subscribe_wild_char_in_middle_c537969(wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point,
                                                             wifi_dut, request, sl_collections, sniffer_filter):
    """Verify whether DUT is throwing an error or not while Subscribe to MQTT server with # included in middle of
    TOPIC name"""

    try:
        topic_wild = "mytest#topic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild, qos=1)
        wifi_dut.interfaces.mqtt.get_saved_firmware_status()
        events = wifi_dut.interfaces.wifi.get_async_events()

        mqtt_connection_error_event = [
            event
            for event in events
            if event.event_type == AsyncEventIdentifiers.MQTT_DISCONNECT_EVENT
        ]
        assert len(mqtt_connection_error_event), "Expected error event not found"
        logger().info("**** MQTT disconnect event received while subscribing with '#' wild card in middle of topic ****")

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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_qos2_connection_failed_c537968(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """Negative Case : QOS2: Verify whether DUT is throwing an error or not while Subscribe/publish to MQTT server with
    TCP connection and publish data over subscribed topic."""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        capture_filename = request.node.name

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=2)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)

        events = wifi_dut.interfaces.wifi.get_async_events()

        mqtt_connection_error_event = [
            event
            for event in events
            if event.event_type == AsyncEventIdentifiers.MQTT_SUBSCRIBE_FAILURE_INDICATION
        ]
        assert len(mqtt_connection_error_event), "Expected error event not found"

        logger().info("**** MQTT connection fails with QOS2 ****")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 4096, "buffer_len": 1600, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_verify_multithread_using_https_and_mqtt_over_ssl_c563984(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, http_server, http_client):
    """
        Test Case ID: C563984

        Objective:
        Verify the functionality of the DUT (Device Under Test) when performing multithreaded operations using HTTPS and MQTT over SSL.

        Steps:
        1. Configure the Wi-Fi DUT to connect to the access point.
        2. Set up SSL certificates for secure communication.
        3. Start HTTPS operations in one thread.
        4. Simultaneously, initiate MQTT operations over SSL in another thread.
        5. Capture network traffic using the Wi-Fi sniffer for analysis.
        6. Verify that both HTTPS and MQTT operations complete successfully without interference.
        7. Ensure proper cleanup of resources after the test.

        Parameters:
        - wifi_sniffer: The Wi-Fi sniffer used to capture network traffic.
        - mqtt_server: The MQTT server used for the test.
        - mqtt_client: The MQTT client used for sending and receiving messages.
        - wifi_access_point: The Wi-Fi access point used for the test.
        - wifi_dut: The Wi-Fi Device Under Test (DUT).
        - request: Pytest request object for test metadata.
        - sl_collections: Collection of utility functions for Wi-Fi operations.
        - sniffer_filter: Filter configuration for the Wi-Fi sniffer.
        - http_server: The HTTP server used for HTTPS operations.
        - http_client: The HTTP client used for sending HTTPS requests.

        Assertions:
        - Verify that HTTPS operations are successful.
        - Ensure MQTT operations over SSL complete without errors.
        - Confirm that no interference occurs between HTTPS and MQTT operations.
        """
    try:
        iter_count=5
        topic = "mytesttopic"
        index_path = "index.html"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        capture_filename = request.node.name
        wifi_dut.interfaces.wifi.set_ssl_certificate(
            str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
            Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
            Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START,
            cert_index=1)

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        mqtt_connection = MQTTParallelThread(wifi_dut=wifi_dut, mqtt_server=mqtt_server,
                                             mqtt_client=mqtt_client,
                                             topic=topic, message=message, iter_count=iter_count)
        mqtt_connection.mqtt_client_connect()

        http_get_connection = HTTPSGET(wifi_dut=wifi_dut, http_server=http_server, index_path=index_path,
                                       http_client=http_client, iter_count=iter_count)
        http_get_connection.http_client_init()
        #Start the Multiple Threads
        mqtt_connection.start()
        http_get_connection.start()
        http_get_connection.wait_for_exit()
        mqtt_connection.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.clear_certificate(cert_index=1)



