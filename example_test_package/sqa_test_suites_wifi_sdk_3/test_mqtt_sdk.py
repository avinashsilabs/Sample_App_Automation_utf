import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116AsyncEventType,
    RS9116PowerSaveModes,
    RS9116MqttQos,
    RS9116CustomFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveProcedureTypes,
    RS9116BLEFeatureBitMap,
    RS9116BLECustomFeatureBitMap
)
from utf.utils.stopwatch import Stopwatch
from utf.utils.time_measurer import TimeMeasurer
from retry import retry
from utf.utils.logger import get_logger
import string
from utf.interfaces.wifi import WlanError
import filecmp
import os
import re
import random
from threading import Thread
from utf.utils.thread_base import ThreadBase
import threading
from typing import Dict
from utf.utils.iperf.iperf_utils import ping
from datetime import datetime
import uuid

"""The testcases added in this file can run below test steps :
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Open MQTT server in the Raspberry pi
        5. Connect to the MQTT server from the DUT
        6. Connect to the MQTT server from the Raspberry pi
        7. Send or receive data on MQTT and verify packet loss tests 

setup requirement:
        1. DUT
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC Wifi Sniffer 

"""


def logger():
    return get_logger(__name__)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut, dut_ip, switch, capture_filename, wifi_access_point, wifi_sniffer, mqtt_server,
                 mqtt_client, ping_count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.dut_ip = dut_ip
        self.switch = switch
        self.capture_filename = capture_filename
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.ping_count = ping_count

    def wifi_bt_powersave(self):
        # The below api puts DUT to power save
        logger().info("Enabling WLAN and BT power save")
        enable_ps = self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_ps, "WLAN power save failed"
        enable_bt_ps = self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "BT power save failed"

    def run(self):
        self.ping_count = 10
        self.wifi_dut.interfaces.wifi.associated = False
        result = self.wifi_dut.interfaces.wifi.version()
        logger().info(f"DUT firmware version: {result}")
        logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)

        mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"DUT MAC_Address: {mac_address}")
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.capture_filename}.pcap"
        )
        for count in range(1, 3):
            try:
                join_fail = 1
                # DUT connects to AP after join_ap API is executed
                logger().info("Joining to the Wifi Access Point")
                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point, thread=True)
                join_fail = 0
                break
            except:
                self.wifi_dut.interfaces.wifi.initialized = False
                logger().info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        if join_fail:
            logger().info(f"Joining to the AP has failed")
            assert join_fail == 0, "Joining to the AP is failed"
        for count in range(1, 3):
            ip_fail = 1
            try:
                # DUT gets ipaddress through DHCP process after start_ip API is executed
                logger().info("DUT gets ipaddress through DHCP ")
                ip_address = self.wifi_dut.interfaces.wifi.start_ip(timeout=60, thread=True)
                ip_fail = 0
                break
            except:
                logger().info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(1)
        if ip_fail:
            logger().info(f"DUT unable to get IP address")
            assert ip_fail == 0, "ip setting in DUT has failed"

        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_address, thread=True)
        logger().info(f"DUT ip : {device_ip}")
        logger().info(f"Initiating ping to DUT ip {device_ip}")
        status = ping(device_ip, 10)
        if status == 1:
            logger().info(f"ping to DUT is successful")
        else:
            logger().info(f"ping to DUT is failed")
        logger().info(f" API to enable wifi and BT powersave")
        self.wifi_bt_powersave()
        events = self.wifi_dut.interfaces.wifi.get_async_events()
        rejoin_error_events = [event
                               for event in events
                               if event.event_type == RS9116AsyncEventType.RejoinError]
        if len(rejoin_error_events):
            logger().info(f" ==== Rejoin error occurred So Rejoining to the AP ======")
            self.run()
        time.sleep(0.1)
        return mac_address


def get_mqtt_list(wifi_sniffer, dut_mac_address, decryption_key: str, print_layers: list, capture_filename,
                  mode=0):
    mqtt_capture_list = []
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {dut_mac_address})'
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}")
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
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
                    logger().info(f"As per sniffer capture MQTT packets sent by DUT..{ta_address}  ->  {mqtt_layer}")
                    mqtt_capture_list.append(tuple([mqtt_layer, packet.sniff_timestamp]))
    return mqtt_capture_list


def ssl_tcp_packet_check(wifi_sniffer, logger, decryption_key: str, dut_mac_address, ap_bssid, print_layers: list,
                         capture_filename, mode=0):
    current_time = time.time()
    updated_capture_file = 'filter_ssl' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    result_ssl = []
    result_tcp = []
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {ap_bssid})'
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}")
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
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
                logger().info("=================================== Layer is TCP =================================")
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


def verify_ps_validation(dut_mac_address, sniffer_filter, wifi_sniffer):
    logger().info(f"Checking for the PS-Poll packets in the sniffer.")
    packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(ta_addr=dut_mac_address,
                                                                                    filter_name='ps_poll')
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
# The test case checks mqtt connection, subscribe and publish feature when mqtt qos associated is qos1
def test_mqtt_qos1_connect_publish_check_dut_behaviour_TC127757(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, dut_mac_address, sniffer_filter
):
    topic = "mytesttopic"
    # The api returns 300 bytes of random data
    message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
    capture_filename = "test_mqtt_qos1_connect_publish_check_dut_behaviour_TC127757"
    wifi_obj = WifiJoin(wifi_dut, wifi_access_point, wifi_sniffer, mqtt_server, mqtt_client, capture_filename)
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    # DUT connects to MQTT server after execution of below api
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, thread=True)
    # mqtt-client connects to MQTT server after execution of below api
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
    time.sleep(5)
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        logger().info("MQTT Client subscribes to the topic with QOS 1")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)
    # publish a message with the dut
    logger().info("DUT will publish message over the topic")
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=RS9116MqttQos.QOS1, thread=True)

    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message " \
                                                "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "mqtt client received message with wrong QOS. expected is QOS1"

    logger().info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    # unsubscribe to the topic
    logger().info("....Unsubscribing to the topic....")
    wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic, thread=True)
    wifi_dut.interfaces.wifi.mqtt_client_disconnect(thread=True)
    wifi_dut.interfaces.wifi.leave()
    verify_ps_validation(dut_mac_address, wifi_sniffer, sniffer_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
# The test case checks mqtt connection, subscribe and publish feature when mqtt qos associated is qos0
def test_mqtt_qos0_connect_publish_max_data_1441bytes_check_dut_behaviour_TC127827(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, dut_mac_address, sniffer_filter
):
    topic = "mytesttopic"
    # The api returns 1441 bytes of random data
    message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1441))
    capture_filename = "test_mqtt_qos0_connect_publish_max_data_1441bytes_check_dut_behaviour_TC127827"
    wifi_obj = WifiJoin(wifi_dut, wifi_access_point, wifi_sniffer, mqtt_server, mqtt_client, capture_filename)
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    # DUT connects to MQTT server after execution of below api
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, thread=True)
    # mqtt-client connects to MQTT server after execution of below api
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
    time.sleep(5)
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        logger().info("MQTT Client subscribes to the topic with QOS 1")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS0)
    # publish a message with the dut
    logger().info("DUT will publish message over the topic")
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=RS9116MqttQos.QOS0, thread=True)
    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message " \
                                                "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop the sniffer")
    # unsubscribe to the topic
    logger().info("MQTT client unsubscribes to the topic")
    wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic, thread=True)
    wifi_dut.interfaces.wifi.mqtt_client_disconnect(thread=True)
    wifi_dut.interfaces.wifi.leave()
    verify_ps_validation(dut_mac_address, wifi_sniffer, sniffer_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(0, 120)])
def test_mqtt_keep_alive_disable_with_qos1_TC127794(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, keep_alive_time, idle_time, dut_mac_address
):
    topic = "mytesttopic"
    # The api returns 300 bytes of random data
    message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
    capture_filename = "test_mqtt_keep_alive_disable_with_qos1_TC127794"
    wifi_obj = WifiJoin(wifi_dut, wifi_access_point, wifi_sniffer, mqtt_server, mqtt_client, capture_filename)
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    # Both DUT and third-party mqtt client connects to MQTT server
    logger().info("Both DUT and third-party mqtt client connects to MQTT server")
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                           keepalive_interval=keep_alive_time, thread=True
                                                           )
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
    time.sleep(5)
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        logger().info("MQTT client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)
    # publish a message with the dut
    logger().info("DUT publishes message over the topic")
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=RS9116MqttQos.QOS1, thread=True)
    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message " \
                                                "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS0"

    logger().info(f"Wait for {idle_time} seconds")
    time.sleep(idle_time)
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(1)
    timestamp = []
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    mqtt_capture_list = get_mqtt_list(wifi_sniffer, dut_mac_address, decryption_key, ["mqtt"], capture_filename)
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


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "mqtt_disconnect"])
# The test case checks mqtt publish message with retain option
def test_mqtt_retain_with_qos1_TC127826(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, dut_mac_address, sniffer_filter
):
    capture_filename = "test_mqtt_retain_with_qos1_TC127826"
    wifi_obj = WifiJoin(wifi_dut, wifi_access_point, wifi_sniffer, mqtt_server, mqtt_client, capture_filename)
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    logger().info("DUT connects to the mqtt server")
    # DUT connects to MQTT server after execution of below api
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, thread=True)
    logger().info("MQTT client connects to the mqtt server")
    # mqtt-client connects to MQTT server after execution of below api
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
    topic = "mytesttopic/1"
    # the below api would generate a message of 300 bytes
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
    # publish a message with the dut with retain 1
    logger().info(f"Publishing message 1 :{message1} with retain bit 1")
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message1.encode(), qos=RS9116MqttQos.QOS1,
                                                 retain=RS9116MqttQos.QOS1, thread=True)
    logger().info(f"Publishing message 2 :{message2} with retain bit 2")
    # publish a message with the dut with retain 1
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message2.encode(), qos=RS9116MqttQos.QOS1,
                                                 retain=RS9116MqttQos.QOS1, thread=True)
    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            logger().info("subscribing to the mqtt client")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)
    except:
        time.sleep(1)

    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        #  mqtt client receives messages
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    logger().info("checking for the received message")
    assert len(msgs) == 1, "No message is received by mqtt-client on subscribed topic"
    assert msgs[0].topic == topic, "topic received is not matched"
    assert msgs[0].payload == message2.encode(), "data received on the topic is not matched"
    logger().info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    # unsubscribe to the topic
    logger().info(f"Unsubscribing to the topic {topic}")
    wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic, thread=True)
    wifi_dut.interfaces.wifi.mqtt_client_disconnect(thread=True)
    wifi_dut.interfaces.wifi.leave()
    verify_ps_validation(dut_mac_address, wifi_sniffer, sniffer_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
# The test case should produce error 0xFFFFFFD3 as username or password is more than 60 bytes
def test_mqtt_check_error_0xFFFFFFD3_C127802(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, dut_mac_address, sniffer_filter
):
    # The api generates 65 bytes of random data
    username = ''.join(random.choices(string.ascii_uppercase + string.digits, k=65))
    capture_filename = "test_mqtt_check_error_0xFFFFFFD3_C127802"
    wifi_obj = WifiJoin(wifi_dut, wifi_access_point, wifi_sniffer, mqtt_server, capture_filename)
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    logger().info(f"username is {username}")
    with pytest.raises(WlanError) as exc_info:
        # DUT tries to connect to mqtt server
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, username=username,
                                                               thread=True)
        logger().info(f"DUT sent {exc_info.value.error_code} code when the username or password is more than 60 bytes")
    assert exc_info.value.error_code == 0xFFFFFFD3, "DUT sent wrong error code, expected is 0xFFFFFFD3"
    logger().info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.mqtt_client_disconnect(thread=True)
    wifi_dut.interfaces.wifi.leave()
    verify_ps_validation(dut_mac_address, wifi_sniffer, sniffer_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
# The test case checks DUT behavior when DUT is trying to connect to MQTT server, but server is not responding
def test_mqtt_invalid_server_TC127801(
        wifi_sniffer, mqtt_server, wifi_access_point, wifi_dut, dut_mac_address, sniffer_filter
):
    capture_filename = "test_mqtt_invalid_server_TC127801"
    wifi_obj = WifiJoin(wifi_dut, wifi_access_point, wifi_sniffer, mqtt_server, capture_filename)
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    logger().info(f"MQTT server is not running at 192.168.100.50")
    with pytest.raises(WlanError) as exc_info:
        # After execution of below api DUT connects to MQTT server
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt,
                                                               mqtt_server="192.168.100.50", thread=True)
        logger().info(f"DUT sent {exc_info.value.error_code} code when MQTT server is not responding")
    assert exc_info.value.error_code == 0xFF87, "DUT sent wrong error code, expected is 0xFF87"
    logger().info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.mqtt_client_disconnect(thread=True)
    wifi_dut.interfaces.wifi.leave()
    verify_ps_validation(dut_mac_address, wifi_sniffer, sniffer_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ble_features": RS9116BLEFeatureBitMap.TXPowerIndex | RS9116BLEFeatureBitMap.GattSyncBit | RS9116BLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": RS9116BLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
        "rejoin_max_retry": 0,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 6})
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
# The test case checks whether the DUT is able to connect to MQTT server over SSL when authentication feature is enabled
def test_mqtt_server_with_ssl_conn_enable_retain_bit_publish_data_C127759(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, dut_mac_address,
):
    topic = "mytesttopic"
    capture_filename = "test_mqtt_server_with_ssl_conn_enable_retain_bit_publish_data_C127759"
    # The api returns 1441 bytes of random data
    message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=550))
    wifi_obj = WifiJoin(wifi_dut, wifi_access_point, wifi_sniffer, mqtt_server, capture_filename)
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    # DUT connects to MQTT server after execution of below api
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt, thread=True)
    # mqtt-client connects to MQTT server after execution of below api
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
    time.sleep(5)
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        logger().info("==== MQTT client subscribes to the topic =====")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS0)
    logger().info("=== Clear the previous received messages ===")
    mqtt_client.interfaces.mqtt.received_messages.clear()
    # publish a message with the dut
    logger().info("===== DUT publishes message over the topic ======")
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message.encode(), qos=RS9116MqttQos.QOS0,
                                                 retain=RS9116MqttQos.QOS1, thread=True)

    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message " \
                                                "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS0, "mqtt-client received message with wrong QOS. expected is QOS0"
    logger().info("Stop the sniffer")
    # unsubscribe to the topic
    logger().info("====== MQTT client unsubscribes to the topic =======")
    wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic, thread=True)
    wifi_dut.interfaces.wifi.mqtt_client_disconnect(thread=True)
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info(f"========== Validation of ssl packet (server hello, client hello, client key exchange, Encrypted "
                  f"Handshake Message ==============")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger().info(f"DECRYPTION KEY-->{decryption_key}")
    ssl_pkt, tcp_pkt = ssl_tcp_packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid,
                                            ["tls", "tcp"], capture_filename, mode=0)
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
    logger().info("Disable the wifi and bt power save")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled, 0)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled, 0)
    logger().info(f"=========Disconnect from DUT=======")
    wifi_dut.interfaces.wifi.leave()
