import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCertificateType,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xMqttQos,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
)
from utf.interfaces.shell.ssh_shell import SSHShell
from utf.utils.logger import get_logger
import string
from utf.interfaces.wifi import WlanError
import re
import random
from utf.utils.thread_base import ThreadBase
from typing import Dict
from datetime import datetime
import uuid
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.sl_status import SLStatus

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


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, capture_filename=None, wifi_access_point=None, wifi_sniffer=None, mqtt_server=None
                 , mqtt_client=None, sl_collections=None, topic=None, sniffer_filter=None, message=None):
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

        time.sleep(1)

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
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_qos0_connect_publish_max_data_TC127827(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, sniffer_filter, request, sl_collections):

    """QOS0: Subscribe to MQTT server with TCP connection and publish maximum data of 1441 bytes oversubscribed topic"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1441))
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

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Unsubscribe from the topic")
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
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS0, timeout=20)

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
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1, timeout=20)

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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_mqtt_check_error_0xFFFFFFD3_C127802(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, sniffer_filter, request, sl_collections, mqtt_client):

    """If username or password is given more than 60 bytes 0xFFFFFFD3 error code should be seen"""

    try:
        username = ''.join(random.choices(string.ascii_uppercase + string.digits, k=65))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        logger().info(f"username is {username}")
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                        is_connection_encrypted=True)

        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt,
                                                               username=username,
                                                               expected_status=SLStatus.SL_STATUS_SI91X_PARAMETER_LENGHT_EXCEED)
        logger().info("DUT sent 0xFFFFFFD3 when the username or password is more than 60 bytes")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
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
        logger().info(f"MQTT server is not running at 192.168.100.50")

        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt,
                                                               mqtt_server="192.168.100.50")
        # logger().info(f"DUT sent {exc_info.value.error_code} code when MQTT server is not responding")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        #wifi_dut.interfaces.wifi.mqtt_client_disconnect()
        #wifi_dut.interfaces.wifi.leave()
        wifi_obj.verify_ps_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
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
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable"])
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
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            logger().info("==== MQTT client subscribes to the topic =====")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=Si91xMqttQos.QOS0)
        logger().info("=== Clear the previous received messages ===")
        mqtt_client.interfaces.mqtt.received_messages.clear()
        logger().info("===== DUT publishes message over the topic ======")
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=Si91xMqttQos.QOS0,
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
        logger().info("Stop the sniffer")
        logger().info("====== MQTT client unsubscribes to the topic =======")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
        #wifi_dut.interfaces.wifi.mqtt_client_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
            f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(wifi_sniffer, decryption_key,
                                                         wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename, mode=0)
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
        logger().info(f"=========Disconnect from DUT=======")
        #wifi_dut.interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
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
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable"])
def test_wifi_sdk_subscribe_mqtt_with_ssl_close_and_subscribe_again_for_5_iter_C127803(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS1: Connect/subscribe to MQTT server with SSL connection and publish data"""

    try:
        iter_count = 5
        for i in range(0, iter_count):
            logger().info(f" ====== Running Iteration : {i} ========")
            topic = "mytesttopic"
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=400))
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
            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client")
            logger().info("Both DUT and third-party mqtt client connects to MQTT server")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            for device in client_devices:
                device.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(5)
            wifi_obj.subscribe_and_publish(mqtt_client=mqtt_client, wifi_dut=wifi_dut, topic=topic, message=message,
                                           qos=Si91xMqttQos.QOS1)
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
                                                        "message " \
                                                        "received is wrong"
            assert msgs[0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"
            logger().info("MQTT client unsubscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
            #wifi_dut.interfaces.wifi.mqtt_client_disconnect()
            logger().info("Stop the sniffer")
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info(
                f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted"
                f"Handshake Message ==============")
            decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
            logger().info(f"DECRYPTION KEY-->{decryption_key}")
            ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(wifi_sniffer, decryption_key, ap_bssid, capture_filename,
                                                             wifi_obj.dut_addr['dut_mac_address'], ["tls", "tcp"],
                                                             mode=0)
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
            #wifi_dut.interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
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
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable"])
def test_wifi_sdk_qos1_mqtt_with_ssl_publish_diff_length_C127789(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS1: Subscribe to MQTT server with SSL connection and publish data with different lengths"""

    try:
        logger().info(f"QOS1: Subscribe to MQTT server with SSL connection and publish data with different lengths"
                      "(1 byte, 10 bytes, 100 bytes, 512 bytes, 1000 bytes, 1340 bytes)")
        topic = "mytesttopic"
        capture_filename = request.node.name
        iter_count = 5
        for i in range(1, iter_count + 1):
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
            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client")
            logger().info("Both DUT and third-party mqtt client connects to MQTT server")
            for device in client_devices:
                device.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(5)
            if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
                logger().info("MQTT client subscribes to the topic")
                mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=Si91xMqttQos.QOS1)

            msg_length = [1, 10, 100, 512, 1000, 1340]
            for length in msg_length:
                logger().info(f" Publish data for length : {length} bytes")
                mqtt_client.interfaces.mqtt.received_messages.clear()
                message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
                logger().info("DUT publishes message over the topic")
                wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=Si91xMqttQos.QOS1)

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
                                                           "message " \
                                                           "received is wrong"
                assert msgs[
                           0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"
            logger().info("MQTT client unsubscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
            #wifi_dut.interfaces.wifi.mqtt_client_disconnect()
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop the sniffer")
            logger().info(
                f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
                f"Handshake Message ==============")
            decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
            logger().info(f"DECRYPTION KEY-->{decryption_key}")
            ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(wifi_sniffer, decryption_key,
                                                             wifi_obj.dut_addr['dut_mac_address'],
                                                             ap_bssid, ["tls", "tcp"], capture_filename, mode=0)
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
            logger().info("===== Disconnect from DUT =======")
            #wifi_dut.interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
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
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable"])
def test_wifi_sdk_qos0_mqtt_with_ssl_publish_diff_length_C127790(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS0: Subscribe to MQTT server with SSL connection and publish data with different lengths"""

    try:
        logger().info(f"QOS0:Subscribe to MQTT server with SSL connection and publish data with different lengths"
                      "(1 byte, 10 bytes, 100 bytes, 512 bytes, 1000 bytes, 1340 bytes)")
        topic = "mytesttopic"
        capture_filename = request.node.name
        iter_count = 5
        for i in range(1, iter_count + 1):
            logger().info(f" ==== Running iteration of : {i} ========")
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                                wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                                sl_collections=sl_collections)
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP BSSID = {ap_bssid}')
            wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client")
            client_devices = [wifi_dut, mqtt_client]
            logger().info("Both DUT and third-party mqtt client connects to MQTT server")
            for device in client_devices:
                device.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(5)
            if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
                logger().info("MQTT client subscribes to the topic")
                mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=Si91xMqttQos.QOS0)

            msg_length = [1, 10, 100, 512, 1000, 1340]
            for length in msg_length:
                logger().info(f" Publish data for length : {length} bytes")
                mqtt_client.interfaces.mqtt.received_messages.clear()
                message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
                logger().info("DUT publishes message over the topic")
                wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=Si91xMqttQos.QOS0)

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
                                                           "message " \
                                                           "received is wrong"
                assert msgs[
                           0].qos == Si91xMqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"
            logger().info("MQTT client unsubscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
            #wifi_dut.interfaces.wifi.mqtt_client_disconnect()
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop the sniffer")
            logger().info(
                f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
                f"Handshake Message ==============")
            decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
            logger().info(f"DECRYPTION KEY-->{decryption_key}")
            ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(wifi_sniffer, decryption_key,
                                                             wifi_obj.dut_addr['dut_mac_address'],
                                                             ap_bssid, ["tls", "tcp"], capture_filename, mode=0)
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
            logger().info("===== Disconnect from DUT =======")
            #wifi_dut.interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)





@pytest.mark.skip()
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
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable"])
# The test case checks whether the DUT is able to connect to MQTT server over SSL when authentication feature is enabled
def test_wifi_sdk_subscribe_mqtt_with_ssl_close_and_subscribe_again_for_30_min_C127798(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS1: Subscribe to MQTT server with SSL connection and publish data , initiate WLAN disconnection and
    do in a loop from scan/connect/ipconfig/subscribe/publish/disconnect for 30 minutes in loop"""

    try:
        loop_watch = Stopwatch()
        while loop_watch.elapsed_sec < 1800:
            logger().info(
                f"============ {loop_watch.elapsed_sec} seconds are completed for connect, subscribe, 400 bytes "
                f"of data publish and close ===========")
            topic = "mytesttopic"
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=400))
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
            logger().info("Both DUT and third-party mqtt client connects to MQTT server")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            for device in client_devices:
                device.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
            time.sleep(5)
            wifi_obj.subscribe_and_publish(mqtt_client, wifi_dut, topic, message, qos=Si91xMqttQos.QOS1)
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
                                                        "message " \
                                                        "received is wrong"
            assert msgs[0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"
            logger().info("MQTT client unsubscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
            #wifi_dut.interfaces.wifi.mqtt_client_disconnect()
            logger().info("Stop the sniffer")
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info(
                f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
                f"Handshake Message ==============")
            decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
            logger().info(f"DECRYPTION KEY-->{decryption_key}")
            ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(wifi_sniffer, decryption_key,
                                                             wifi_obj.dut_addr['dut_mac_address'],
                                                             ap_bssid, ["tls", "tcp"], capture_filename, mode=0)
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
            #wifi_dut.interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
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
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable"])
# The test case checks whether the DUT is able to connect to MQTT server over TCP when authentication feature is enabled
def test_wifi_sdk_subscribe_mqtt_qos0_with_ssl_subscribe_unscribe_for_30_min_C127788(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, sl_collections):
    """QOS0: Subscribe to MQTT server with SSL connection and publish data. Unsubscribe from the subscribed topic and
    do the same Subscribe/Unsubscribe for 30 minutes in loop"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=400))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        client_devices = [wifi_dut, mqtt_client]
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        for device in client_devices:
            device.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
        time.sleep(5)
        loop_watch = Stopwatch()
        while loop_watch.elapsed_sec < 1800:
            logger().info(f"====== {loop_watch.elapsed_sec} seconds are completed =======")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            wifi_obj.subscribe_and_publish(mqtt_client, wifi_dut, topic, message, qos=Si91xMqttQos.QOS0)
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
                                                        "message " \
                                                        "received is wrong"
            assert msgs[0].qos == Si91xMqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"
            logger().info("MQTT client unsubscribes to the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)
        #wifi_dut.interfaces.wifi.mqtt_client_disconnect()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted"
                      f"Handshake Message ==============")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(wifi_sniffer, decryption_key,
                                                         wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename, mode=0)
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
        #wifi_dut.interfaces.wifi.leave()
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
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
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


@pytest.mark.skip()
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
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(180, 220)])
def test_wifi_sdk_mqtt_keep_alive_180_ssl_connection_with_qos0_TC127786(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, keep_alive_time, idle_time,
        sl_collections):
    """QOS0: Subscribe to MQTT server with SSL connection and publish data. Verify MQTT keep alive functionality
    when keep alive period configured for 180 seconds"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=400))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                               keepalive_interval=keep_alive_time)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
        time.sleep(5)
        wifi_obj.subscribe_and_publish(mqtt_client, wifi_dut, topic, message, qos=Si91xMqttQos.QOS0)
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
        logger().info(f"Wait for {idle_time} seconds")
        time.sleep(200)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(wifi_sniffer, decryption_key,
                                                         wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename, mode=0)
        assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
            "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt), \
            "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
            "Unable to find 'Change Cipher Spec' message"
        logger().info(f"===== TCP Packet decryprtion and check SYN, FIN, ACK, FIN ACK ======")

        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in message), f"Unable to find SYN packet "
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in message), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in message), \
            "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in message), \
            "Unable to find FIN ACK "

        logger().info(f"=========Disconnect from DUT=======")
        #wifi_dut.interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
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
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(0, 120)])
def test_wifi_sdk_mqtt_keep_alive_disable_ssl_connection_with_qos0_TC127795(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, keep_alive_time, idle_time,
        sl_collections):
    """QOS0: Subscribe to MQTT server with SSL connection and publish data. Check MQTT keep alive functionality
    when keep alive period is 0"""

    try:
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=400))
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                               keepalive_interval=keep_alive_time)
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
        time.sleep(5)
        wifi_obj.subscribe_and_publish(mqtt_client, wifi_dut, topic, message, qos=Si91xMqttQos.QOS0)
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
        logger().info(f"Wait for {idle_time} seconds")
        time.sleep(200)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)
        timestamp = []
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        ssl_pkt, tcp_pkt = wifi_obj.ssl_tcp_packet_check(wifi_sniffer, decryption_key,
                                                         wifi_obj.dut_addr['dut_mac_address'],
                                                         ap_bssid, ["tls", "tcp"], capture_filename, mode=0)
        assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
            "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Encrypted Handshake Message" in ssl_pkt), \
            "Unable to find 'Encrypted Handshake Message' "
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
            "Unable to find 'Change Cipher Spec' message"
        logger().info(f"===== TCP Packet decryprtion and check SYN, FIN, ACK, FIN ACK ======")

        assert (message for message in tcp_pkt if "Flags: 0x002 (SYN)" in message), f"Unable to find SYN packet "
        assert (message for message in tcp_pkt if "Flags: 0x012 (SYN, ACK)" in message), "Unable to find SYN ACK"
        assert (message for message in tcp_pkt if "Flags: 0x010 (ACK)" in message), \
            "Unable to find ACK"
        assert (message for message in tcp_pkt if "Flags: 0x011 (FIN, ACK)" in message), \
            "Unable to find FIN ACK "
        logger().info(f"=========Disconnect from DUT=======")
        #wifi_dut.interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
