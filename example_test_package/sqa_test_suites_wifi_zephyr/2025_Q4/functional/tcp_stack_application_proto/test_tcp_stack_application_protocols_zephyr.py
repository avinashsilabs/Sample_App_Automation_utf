import time
import pytest

from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger

import random
import string
from utf_wifi_zephyr.devices.si91x import Si91xBSDSocketParams, ZephyrHttpMethods
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
import uuid
from datetime import datetime
from typing import Dict
import re
from typing import Union
import ipaddress
from base64 import b64decode
from threading import Thread

"""The testcases added in this file run below test steps for DUT(Soc917)
        1. Configuration of DUT in 2G : gnbax
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP or UDP socket(Client/server) at DUT/RASPBERRY - PI
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
        8. Verify MQTT, HTTP CLIENT,  WEB SOCKET, ICMP features
       

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. NUC device for Sniffer

    Author: Vinod.G
"""


def text_generator(size=1000):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


class WebsocketEventHandler:
    def __init__(self):
        self.client_connected = False
        self.client_disconnected = False
        self.message_received = ""

    def on_ws_client_connected(self, client: dict):
        # logger().info(f"what is the message getting received 1 ")
        self.client_connected = True

    def on_ws_client_disconnected(self, client: dict):
        # logger().info(f"what is the message getting received 2")
        self.client_disconnected = True

    def on_ws_message_received(self, client: dict, message: Union[str, bytes]):
        logger().info(f"what is the message getting received {message} ")
        self.message_received = message
        logger().info(f"received message {len(self.message_received)}")


def logger():
    return get_logger(__name__)


def ap_switch(switch, ap_turn_off_time, start_delay):
    time.sleep(start_delay)
    logger().info(f"Turn off AP for {ap_turn_off_time} seconds")
    switch.interfaces.pdu_switch.turn_off(delay=1)
    time.sleep(ap_turn_off_time)
    switch.interfaces.pdu_switch.turn_on()
    logger().info("AP is turn on")


def random_ipv6_addr(network):
    """
    Generate a random IPv6 address in the given network
    Example: random_ipv6_addr("fd66:6cbb:8c10::/48")
    Returns an IPv6Address object.
    """
    net = ipaddress.IPv6Network(network)
    # Which of the network.num_addresses we want to select?
    addr_no = random.randint(0, net.num_addresses)
    # Create the random address by converting to a 128-bit integer, adding addr_no and converting back
    network_int = int.from_bytes(net.network_address.packed, byteorder="big")
    addr_int = network_int + addr_no
    addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
    return addr


class WifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, sniffer_filter=None, wifi_sniffer=None,
                 zephyr_wifi_collections=None, test_name=None, remote_socket_factory=None, ap_mac_address=None,
                 remote_socket=None, allocate_static_ip=0, mqtt_client=None, mqtt_server=None, http_server=None,
                 http_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.test_name = test_name
        self.dut_addr = None
        self.device_ip = None
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.enc = "ccmp"
        self.remote_socket_factory = remote_socket_factory
        self.remote_socket = remote_socket
        self.allocate_static_ip = allocate_static_ip
        self.mqtt_client = mqtt_client
        self.mqtt_server = mqtt_server
        self.http_server = http_server
        self.http_client = http_client

    def run(self):
        try:
            if self.allocate_static_ip:
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, retry_count=3,
                                                                                  wifi_access_point=self.wifi_access_point,
                                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                                  ping_after_power_save=False,
                                                                                  enc=self.enc, ip_config_disable=1)
            else:
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, retry_count=3,
                                                                                  wifi_access_point=self.wifi_access_point,
                                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                                  ping_after_power_save=False,
                                                                                  enc=self.enc)
                logger().info(
                    f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

    def tcp_server_single_socket(self, port=5001, server_ip=None, data_length=100, time_seconds=30):
        logger().info(f"\n Starting the Remote Socket Server \n")
        self.remote_socket.interfaces.socket.start_server(port=port)
        socket_id = self.wifi_dut.interfaces.wifi.socket(domain=Si91xBSDSocketParams.AF_INET,
                                                         stream_type=Si91xBSDSocketParams.SOCK_STREAM,
                                                         protocol=Si91xBSDSocketParams.IPPROTO_TCP)
        logger().info(f"Socket open successfully : {socket_id}")
        self.wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_id, device_ip=self.dut_addr['device_ip'], port=port, timeout=5)

        logger().info("DUT is connecting to server socket")
        for count in range(3):
            connect_status = False
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_id, server_ip, port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                assert connect_status, "Socket connection failed in DUT"
        logger().info("*********** Socket connection is successful ************")
        sent_data = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=data_length)
        )

        sw = Stopwatch()
        t_end = time_seconds
        while sw.elapsed_sec <= t_end:
            time_left = int((t_end - sw.elapsed_sec) / 60)
            logger().info(f"*************** Remaining time to send data: '{time_left}' minutes ***************")
            try:
                status, data = self.wifi_dut.interfaces.wifi.send(
                    socket_fd=socket_id, data=sent_data
                )
                if status != 0:
                    return socket_id
                received_data = (
                    self.remote_socket.interfaces.socket.recv_data_tcp(len(sent_data))
                )
                logger().info(f"\nReceived Data: {received_data}\n")
                assert (
                        sent_data == received_data
                ), f"Data mismatch in sent and received data"
            except Exception as e:
                logger().info(
                    f"Socket Data Transfer Failed Within Duration"
                )

        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        logger().info(f"Stopping the Remote Socket Server")
        self.remote_socket.interfaces.socket.stop()

    def udp_server_single_socket(self, port=5001, server_ip=None, data_length=100, time_seconds=30, tx_rx_test=0):
        logger().info(f"\n Starting the Remote Socket Server \n")
        self.remote_socket.interfaces.socket.start_server(port=port, socket_type=1)
        socket_id = self.wifi_dut.interfaces.wifi.socket(domain=Si91xBSDSocketParams.AF_INET,
                                                         stream_type=Si91xBSDSocketParams.SOCK_DGRAM,
                                                         protocol=Si91xBSDSocketParams.IPPROTO_UDP)
        logger().info(f"Socket open successfully : {socket_id}")
        self.wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_id, device_ip=self.dut_addr['device_ip'], port=port, timeout=5)
        if tx_rx_test == 0:
            sw = Stopwatch()
            t_end = time_seconds
            while sw.elapsed_sec <= t_end:
                time_left = int((t_end - sw.elapsed_sec) / 60)
                logger().info(f"*************** Remaining time to send data: '{time_left}' minutes ***************")
                try:
                    sent_data = "".join(
                        random.choices(string.ascii_uppercase + string.digits, k=data_length)
                    )
                    time.sleep(1)
                    self.wifi_dut.interfaces.wifi.sendto(
                        socket_fd=socket_id, data=sent_data, ip_address=server_ip, port=port
                    )
                    received_data = (
                        self.remote_socket.interfaces.socket.recv_data_udp(len(sent_data))
                    )
                    logger().info(f"\nReceived Data: {received_data}\n")
                    assert (
                            sent_data == received_data
                    ), f"Data mismatch in sent and received data"
                except Exception as e:
                    logger().info(
                        f"Socket Data Transfer Failed Within Duration"
                    )
        else:
            sw = Stopwatch()
            t_end = time_seconds
            while sw.elapsed_sec <= t_end:
                time_left = int((t_end - sw.elapsed_sec) / 60)
                logger().info(f"*************** Remaining time to send data: '{time_left}' minutes ***************")
                tx_buffer = "".join(
                    random.choices(string.ascii_uppercase + string.digits, k=data_length)
                )

                buffer_length = len(tx_buffer)
                self.remote_socket.interfaces.socket.send_data_udp(tx_buffer, server_ip, port=port)
                time.sleep(1)
                buffer_rx = self.wifi_dut.interfaces.wifi.recvfrom(socket_id, buffer_length)

                logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{socket_id} opened in the DUT is not matched"
                logger().info("Data sent by remote peer and received on DUT is matching")

        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        logger().info(f"Stopping the Remote Socket Server")
        self.remote_socket.interfaces.socket.stop()

    def icmp_send_test(self, target_ip=None, packet_count=100, timeout_ms=1000,
                       success_threshold=80):
        """
        Send ICMP packets and validate success rate

        Arguments:
            target_ip - Target IP address to ping
            packet_count - Number of ICMP packets to send (default: 100)
            timeout_ms - Timeout for each packet in milliseconds (default: 1000ms)
            success_threshold - Minimum success percentage required (default: 80%)

        Returns:
            bool - True if success rate meets threshold, False otherwise
        """
        logger().info(f"\n *** Starting ICMP Send Test *** \n")
        logger().info(f"Target IP: {target_ip}")
        logger().info(f"Packet Count: {packet_count}")
        logger().info(f"Timeout: {timeout_ms}ms")
        logger().info(f"Success Threshold: {success_threshold}%")

        if not target_ip:
            target_ip = self.target_ip

        try:
            # Send ICMP packets using the DUT's icmp_ping method
            logger().info(f"Sending {packet_count} ICMP packets to {target_ip}")

            # Use the icmp_ping method from the WiFi interface
            data = self.wifi_dut.interfaces.wifi.icmp_ping(
                target_ip=target_ip,
                packet_count=packet_count,
                timeout_ms=timeout_ms,
                ip_version=4,
                timeout=120  # Overall timeout for the operation
            )

            success_count = data

            # Calculate success percentage
            success_percentage = (success_count / packet_count) * 100
            logger().info(f"Success Rate: {success_percentage:.2f}%")

            # Validate against threshold
            if success_percentage >= success_threshold:
                logger().info(
                    f"✓ ICMP test PASSED - Success rate {success_percentage:.2f}% meets threshold {success_threshold}%")
                return True
            else:
                logger().error(
                    f"✗ ICMP test FAILED - Success rate {success_percentage:.2f}% below threshold {success_threshold}%")
                return False


        except Exception as e:
            logger().error(f"ICMP ping operation failed: {str(e)}")
            return False

    def get_igmp_list(
            self, dut_mac_address, decryption_key: str, print_layers: list, capture_filename
    ) -> Dict[str, int]:
        igmp_capture_list = []
        current_time = time.time()
        updated_capture_file = (
                "filter_"
                + capture_filename
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
                        igmp_layer = str(layer)
                        logger().info(
                            f"As per sniffer capture IGMP packets sent by DUT..{ta_address}  ->  {igmp_layer}"
                        )
                        igmp_capture_list.append(
                            tuple([igmp_layer, packet.sniff_timestamp])
                        )
        return igmp_capture_list

    def validate_datetime_string(self, date_time_string):
        """
        Validate the date/time string received from SNTP query

        Arguments:
            date_time_string - Date/time string from SNTP response

        Returns:
            dict - Validation result with parsed datetime and format info
        """
        validation_result = {
            'valid': False,
            'parsed_datetime': None,
            'format_detected': None,
            'error': None
        }

        if not date_time_string or not isinstance(date_time_string, str):
            validation_result['error'] = "Invalid or empty date/time string"
            return validation_result

        # Common datetime formats that SNTP might return
        datetime_formats = [
            "%Y-%m-%d %H:%M:%S",  # 2024-01-15 14:30:45
            "%a %b %d %H:%M:%S %Y",  # Mon Jan 15 14:30:45 2024
            "%Y/%m/%d %H:%M:%S",  # 2024/01/15 14:30:45
            "%d-%m-%Y %H:%M:%S",  # 15-01-2024 14:30:45
            "%Y-%m-%d %H:%M:%S UTC",  # 2024-01-15 14:30:45 UTC
            "%Y-%m-%dT%H:%M:%SZ",  # 2024-01-15T14:30:45Z (ISO format)
            "%Y-%m-%dT%H:%M:%S",  # 2024-01-15T14:30:45
        ]

        # Clean up the string (remove extra whitespace, newlines)
        cleaned_string = date_time_string.strip()

        # Try to parse with different formats
        for fmt in datetime_formats:
            try:
                parsed_dt = datetime.strptime(cleaned_string, fmt)
                validation_result['valid'] = True
                validation_result['parsed_datetime'] = parsed_dt
                validation_result['format_detected'] = fmt

                # Additional validation: check if the datetime is reasonable
                current_time = datetime.now()
                time_diff = abs((current_time - parsed_dt).total_seconds())

                # Allow up to 1 hour difference (considering timezone differences)
                if time_diff > 3600:
                    logger().warning(f"Large time difference detected: {time_diff} seconds")
                    logger().warning(f"Current time: {current_time}, SNTP time: {parsed_dt}")

                return validation_result

            except ValueError:
                continue

        # If no standard format worked, try regex patterns for custom formats
        try:
            # Look for patterns like "Date and Time: ..." or timestamp formats
            patterns = [
                r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
                r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',
                r'(\d{1,2}-\d{1,2}-\d{4}\s+\d{2}:\d{2}:\d{2})',
            ]

            for pattern in patterns:
                match = re.search(pattern, cleaned_string)
                if match:
                    extracted_time = match.group(1)
                    # Try to parse the extracted time
                    for fmt in datetime_formats:
                        try:
                            parsed_dt = datetime.strptime(extracted_time, fmt)
                            validation_result['valid'] = True
                            validation_result['parsed_datetime'] = parsed_dt
                            validation_result['format_detected'] = f"Regex: {pattern} -> {fmt}"
                            return validation_result
                        except ValueError:
                            continue
        except Exception as regex_error:
            logger().warning(f"Regex parsing failed: {str(regex_error)}")

        validation_result['error'] = f"Unable to parse date/time string: '{cleaned_string}'"
        return validation_result

    def subscribe_and_publish(self, qos=0, keep_alive=60, check_keep_alive=0, idle_time=0):

        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt,
                                                                    keep_alive_time=keep_alive)

        logger().info(".....MQTT Client connects to MQTT server.....")
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(2)
        if qos == 0:
            dut_subscribe_topic = "mytesttopic_qos0_dut"
            topic = "mytesttopic_qos0"
        elif qos == 1:
            dut_subscribe_topic = "mytesttopic_qos1_dut"
            topic = "mytesttopic_qos1"
        else:
            dut_subscribe_topic = "mytesttopic_qos2_dut"
            topic = "mytesttopic_qos2"

        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
        client_message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))

        logger().info("MQTT Client subscribes to the topic")
        self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=qos)

        logger().info("DUT subscribes to the topic")
        self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=dut_subscribe_topic, qos=qos)

        logger().info("DUT publishes message over the topic")
        publish_response = self.wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=qos,
                                                                             timeout=20)
        logger().info(f"publish response-----------> {publish_response}")
        time.sleep(2)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        if qos == 0:
            assert msgs[0].qos == qos, "DUT sent message with wrong QOS. expected is QOS0"
        if qos == 1:
            assert msgs[0].qos == qos, "DUT sent message with wrong QOS. expected is QOS1"
        if qos == 2:
            assert msgs[0].qos == qos, "DUT sent message with wrong QOS. expected is QOS2"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"

        self.mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=dut_subscribe_topic, payload=client_message, qos=qos)
        data = self.wifi_dut.interfaces.mqtt.mqtt_client_set_idle(sync_timeout=10000)

        topic_match = re.search(r"topic\s*-\s*['\"]([^'\"]+)['\"]", data)
        topic_receive = topic_match.group(1) if topic_match else None

        # Extract payload (after "payload:")
        payload_match = re.search(r"payload:\s*(.+?)(?:\n|$)", data, re.IGNORECASE)
        payload_receive = payload_match.group(1).strip() if payload_match else None

        assert topic_receive == dut_subscribe_topic, "No message received by DUT on MQTT on subscribed topic"
        assert payload_receive == client_message, "No message is received by DUT on MQTT on subscribed topic or " \
                                                  "message received is wrong"

        self.wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic, qos=qos)

        if check_keep_alive:
            self.wifi_dut.interfaces.mqtt.mqtt_client_set_idle(sync_timeout=idle_time, keep_alive_enable=1)

        self.wifi_dut.interfaces.mqtt.mqtt_client_disconnect()

    def get_mqtt_list(self, dut_mac_address, decryption_key, print_layers, capture_file_name):
        mqtt_capture_list = []
        current_time = time.time()
        updated_capture_file = 'filter_' + capture_file_name + '_' + str(
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

    def delta_between_dhcp_req_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff = []
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()

        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                time_diff.append(float(time_delta_from_previous_packet))

        logger().info(time_diff)
        filter_file.close()
        return time_diff

    def websocket_send_and_receive(self, port=80, server_ip=""):
        host_name = "example.com"
        resource_name = "/websocket"
        socket_id = self.wifi_dut.interfaces.wifi.socket(domain=Si91xBSDSocketParams.AF_INET,
                                                         stream_type=Si91xBSDSocketParams.SOCK_STREAM,
                                                         protocol=Si91xBSDSocketParams.IPPROTO_TCP)
        logger().info(f"Socket open successfully : {socket_id}")
        self.wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_id, device_ip=self.dut_addr['device_ip'], port=5001, timeout=5)

        logger().info("DUT is connecting to server socket")
        for count in range(3):
            connect_status = False
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_id, server_ip, port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                assert connect_status, "Socket connection failed in DUT"

        ws_handler = WebsocketEventHandler()
        self.http_server.interfaces.http.set_fn_on_websocket_client_connected(
            ws_handler.on_ws_client_connected
        )
        self.http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
            ws_handler.on_ws_client_disconnected
        )
        self.http_server.interfaces.http.set_fn_on_websocket_message_received(
            ws_handler.on_ws_message_received
        )
        websockcet_fd = self.wifi_dut.interfaces.wifi.websocket_connect(socket_id, host_name, resource_name)
        iter_count = 10
        for i in range(iter_count):
            time.sleep(1)
            data = text_generator(size=20)
        self.wifi_dut.interfaces.wifi.websocket_send(websockcet_fd, data)
        assert ws_handler.message_received == data, f"Data sent by DUT and received on websocket server is not matched in {iter_count} iteration"
        iter_count = 3
        for i in range(iter_count):
            data = text_generator(size=10)
            length = len(data)
            self.http_server.interfaces.http.send_message_to_websocket_clients(data)
            data_buffer = self.wifi_dut.interfaces.wifi.websocket_recv(websockcet_fd, buffer_length=length)
            assert data == data_buffer, f"Data sent by Websocket server and received by DUT is not matched in  {iter_count} iteration"
        self.wifi_dut.interfaces.wifi.websocket_disconnect(websockcet_fd)
        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)

    def http_get_put_post(self, port=80, server_ip="", url="", method=ZephyrHttpMethods.GET, payload=""):
        try:
            socket_id = self.wifi_dut.interfaces.wifi.socket(domain=Si91xBSDSocketParams.AF_INET,
                                                             stream_type=Si91xBSDSocketParams.SOCK_STREAM,
                                                             protocol=Si91xBSDSocketParams.IPPROTO_TCP)
            logger().info(f"Socket open successfully : {socket_id}")
            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=socket_id, device_ip=self.dut_addr['device_ip'], port=5001, timeout=5)

            logger().info("DUT is connecting to server socket")
            for count in range(3):
                connect_status = False
                try:
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                        socket_id, server_ip, port)
                    connect_status = True
                    break
                except:
                    logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                    assert connect_status, "Socket connection failed in DUT"

            if method == ZephyrHttpMethods.GET:

                http_content_dut = self.wifi_dut.interfaces.wifi.http_client_req(socket_id, ZephyrHttpMethods.GET, url,
                                                                                 server_ip)
                status_client, content_client = self.http_client.interfaces.http.http_get(
                    self.http_server.interfaces.http, url)
                assert status_client, "failed to load the https data"
                logger().info(f"http dut response--------->  {http_content_dut}")
                logger().info(f"http client response---------->{content_client}")
                http_data = http_content_dut.split(":")[1]
                http_data_decode = b64decode(http_data)
                logger().info(f"http dut response after decode ---------> {http_data_decode}")
                http_data_decode = http_data_decode.decode()

                match = re.search(r'<html.*', http_data_decode, re.DOTALL | re.IGNORECASE)
                if match:
                    http_content = match.group(0)
                    logger().info("http_content:", http_content)
                else:
                    http_content = ""
                    logger().info("<html' not found in the string")
                assert http_content == content_client.decode(), "fetched data is not same as expected data"
            elif method == ZephyrHttpMethods.POST:
                self.wifi_dut.interfaces.wifi.http_client_req(socket_id, ZephyrHttpMethods.POST, url,
                                                              server_ip, payload=payload)
            else:

                self.wifi_dut.interfaces.wifi.http_client_req(socket_id, ZephyrHttpMethods.PUT, url,
                                                              server_ip, payload=payload)

        except:
            logger().info("HTTP GET, POST, or PUT METHOD FAILED")
        finally:
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_tcp_open_send_close_socket_c19347(
        sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections, wifi_sniffer, request,
        remote_socket, wifi_client):
    """This test case Verifies the tcp client socket open, send data,close functionality"""
    try:
        port = 5001
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections, test_name=test_name,
                                     sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, remote_socket=remote_socket)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.tcp_server_single_socket(port=port, server_ip=server_ip, data_length=100)

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_udp_open_send_close_socket_c39347(
        sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections, wifi_sniffer, request,
        remote_socket, wifi_client):
    """This test case Verifies the udp client socket  open, send data,close functionality"""
    try:
        port = 5001
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections, test_name=test_name,
                                     sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, remote_socket=remote_socket)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.udp_server_single_socket(port=port, server_ip=server_ip, data_length=100)

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_tcp_server_socket_open_listen_accept_receive_close_c19360(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                            request,
                                                                            zephyr_wifi_collections,
                                                                            sniffer_filter, remote_socket_factory,
                                                                            wifi_client):
    """This test case Verifies the tcp server socket open, bind, listen, accept, receive data,close functionality """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections, test_name=test_name,
                                     sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        socket_id = wifi_dut.interfaces.wifi.socket(domain=Si91xBSDSocketParams.AF_INET,
                                                    stream_type=Si91xBSDSocketParams.SOCK_STREAM,
                                                    protocol=Si91xBSDSocketParams.IPPROTO_TCP)
        logger().info(f"Socket open successfully : {socket_id}")
        logger().info(f"Successfully opened tcp socket and socket id received is {socket_id} which is expected")
        local_port = 5001

        wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_id, device_ip=wifi_thread.dut_addr['device_ip'], port=local_port, timeout=5)

        wifi_dut.interfaces.wifi.listen(socket_fd=socket_id, backlog=0)

        ThreadBase.call_functions_simultaneously(
            [
                (wifi_dut.interfaces.wifi.accept, socket_id, 1),
                (
                    client_socket.connect_client_tcp,
                    wifi_thread.dut_addr['device_ip'],
                    local_port,
                ),
            ],
            timeout=10,
        )

        tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
        buffer_length = len(tx_buffer)
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            logger().info(f"Remote peer sending data over socket {socket_id} and data:{tx_buffer}")
            client_socket.send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            buffer_rx = wifi_dut.interfaces.wifi.recv((socket_id + 1), buffer_length)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{socket_id} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id + 1)
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        client_socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_udp_open_receive_close_socket_c39348(
        sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections, wifi_sniffer, request,
        remote_socket, wifi_client):
    """This test case Verifies the udp server socket open, bind, receive data,close functionality"""
    try:
        port = 5001
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections, test_name=test_name,
                                     sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, remote_socket=remote_socket)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        wifi_thread.udp_server_single_socket(port=port, server_ip=wifi_thread.dut_addr['device_ip'], data_length=100,
                                             tx_rx_test=1)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_tcp_open_send_close_socket_for_30_min_c29347(
        sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections, wifi_sniffer, request,
        remote_socket, wifi_client):
    """This test case Verifies the tcp client socket open, send data,close functionality for multiple iterations"""
    try:
        port = 5001
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections, test_name=test_name,
                                     sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, remote_socket=remote_socket)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        sw = Stopwatch()
        t_end = (1 * 60)
        while sw.elapsed_sec <= t_end:
            time_left = int((t_end - sw.elapsed_sec) / 60)
            logger().info(f"*************** Remaining time to complete test is: '{time_left}' minutes ***************")
            wifi_thread.tcp_server_single_socket(port=port, server_ip=server_ip, data_length=100, time_seconds=1)

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_tcp_server_socket_open_listen_accept_receive_close_for_30_min_c29360(wifi_sniffer, wifi_dut,
                                                                                       wifi_access_point,
                                                                                       request,
                                                                                       zephyr_wifi_collections,
                                                                                       sniffer_filter,
                                                                                       remote_socket_factory,
                                                                                       wifi_client):
    """The test case verified tcp server socket open, listen, accept,  receive data, and close functionality multiple iterations"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections, test_name=test_name,
                                     sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        sw = Stopwatch()
        t_end = (1 * 60)
        local_port = 5001
        while sw.elapsed_sec <= t_end:
            time_left = int((t_end - sw.elapsed_sec) / 60)
            logger().info(f"*************** Remaining time to complete test is: '{time_left}' minutes ***************")
            client_socket = remote_socket_factory.interfaces.socket.create_socket()
            socket_id = wifi_dut.interfaces.wifi.socket(domain=Si91xBSDSocketParams.AF_INET,
                                                        stream_type=Si91xBSDSocketParams.SOCK_STREAM,
                                                        protocol=Si91xBSDSocketParams.IPPROTO_TCP)
            logger().info(f"Socket open successfully : {socket_id}")
            logger().info(f"Successfully opened tcp socket and socket id received is {socket_id} which is expected")
            local_port = local_port + 1
            wifi_dut.interfaces.wifi.bind(
                socket_fd=socket_id, device_ip=wifi_thread.dut_addr['device_ip'], port=local_port, timeout=5)

            wifi_dut.interfaces.wifi.listen(socket_fd=socket_id, backlog=0)

            ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.accept, socket_id, 1),
                    (
                        client_socket.connect_client_tcp,
                        wifi_thread.dut_addr['device_ip'],
                        local_port,
                    ),
                ],
                timeout=10,
            )

            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            sw_receive = Stopwatch()
            while sw_receive.elapsed_sec < 10:
                logger().info(f"Remote peer sending data over socket {socket_id} and data:{tx_buffer}")
                client_socket.send_data_tcp(tx_buffer, use_server_socket=False)
                time.sleep(1)
                buffer_rx = wifi_dut.interfaces.wifi.recv((socket_id + 1), buffer_length)
                logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{socket_id} opened in the DUT is not matched"
                logger().info("Data sent by remote peer and received on DUT is matching")

            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id + 1)
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
            client_socket.socket_close_indication(1)
            logger().info("Successfully closed opened socket in the DUT")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_icmp_ipv4_c50001(
        sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections,
        wifi_sniffer, request, wifi_client):
    """
    Test case to verify ICMP packet transmission functionality.

    This test sends 100 ICMP packets and validates that at least 80% succeed.

    Test Steps:
    1. Connect DUT to WiFi access point
    2. Configure IP address via DHCP
    3. Send 100 ICMP packets to gateway/target IP
    4. Validate that success rate is >= 80%
    5. Log detailed statistics

    Pass Criteria:
    - At least 80% of ICMP packets should succeed
    """
    try:
        test_name = request.node.name

        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # Get target IP (use gateway or client IP)
        target_ip = wifi_client.interfaces.wifi.get_ip_address() if wifi_client else None

        # Initialize WiFi connection thread
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
        )

        # Start WiFi connection
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        # If no specific target IP provided, use gateway
        if not target_ip:
            # Get gateway IP from DUT's network configuration
            ip_config = wifi_dut.interfaces.wifi.get_ip_config()
            target_ip = ip_config.get('gateway', '8.8.8.8')  # Fallback to Google DNS

        logger().info(f"Using target IP for ICMP test: {target_ip}")

        # Execute ICMP send test
        test_result = wifi_thread.icmp_send_test(
            target_ip=target_ip,
            packet_count=100,
            timeout_ms=1000,
            success_threshold=80
        )

        # Assert test result
        assert test_result, "ICMP send test failed - success rate below 80% threshold"

        # Log MAC addresses for reference
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC ADDRESS: {ap_mac_address}")

        # Stop sniffer if it was started
        if wifi_sniffer:
            logger().info("Stopping sniffer")
            wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().error(f"Test failed with exception: {str(e)}")
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sntp_multiple_queries_c60003(
        sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections,
        wifi_sniffer, request, wifi_client):
    """
    Test case to verify SNTP functionality with multiple consecutive queries.

    This test performs multiple SNTP queries to validate consistency and reliability.

    Test Steps:
    1. Connect DUT to WiFi access point
    2. Configure IP address via DHCP
    3. Initialize SNTP client
    4. Perform 3 consecutive SNTP queries
    5. Validate all responses
    6. Close SNTP context

    Pass Criteria:
    - All SNTP queries should succeed
    - All date/time responses should be valid
    - Time progression should be logical between queries
    """
    try:
        test_name = request.node.name
        query_count = 3

        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # Initialize WiFi connection thread
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
        )

        # Start WiFi connection
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        # Log MAC addresses for reference
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC ADDRESS: {ap_mac_address}")

        # Initialize SNTP once
        logger().info("Initializing SNTP client for multiple queries...")
        status, init_data = wifi_dut.interfaces.wifi.sntp_init(port=123,
                                                               ip_version=4,
                                                               timeout=30
                                                               )
        logger().info(f"SNTP Init Status: {status}")

        query_results = []

        # Perform multiple queries
        for i in range(query_count):
            logger().info(f"Performing SNTP query {i + 1}/{query_count}...")

            try:
                date_time_string = wifi_dut.interfaces.wifi.sntp_query(
                    timeout_ms=5000,
                    timeout=30
                )

                validation_result = wifi_thread.validate_datetime_string(date_time_string)

                query_result = {
                    'query_number': i + 1,
                    'date_time': date_time_string,
                    'validation_passed': validation_result['valid'],
                    'parsed_datetime': validation_result.get('parsed_datetime'),
                    'error': validation_result.get('error')
                }

                query_results.append(query_result)

                logger().info(f"Query {i + 1} Result: {date_time_string}")
                logger().info(f"Query {i + 1} Valid: {validation_result['valid']}")

                if not validation_result['valid']:
                    logger().error(f"Query {i + 1} validation failed: {validation_result['error']}")

                # Wait between queries
                if i < query_count - 1:
                    time.sleep(2)

            except Exception as query_error:
                logger().error(f"Query {i + 1} failed: {str(query_error)}")
                query_results.append({
                    'query_number': i + 1,
                    'date_time': None,
                    'validation_passed': False,
                    'error': str(query_error)
                })

        # Close SNTP context
        logger().info("Closing SNTP context...")
        close_status, close_data = wifi_dut.interfaces.wifi.sntp_close(timeout=10)
        logger().info(f"SNTP Close Status: {close_status}")

        # Validate results
        successful_queries = [r for r in query_results if r['validation_passed']]
        success_rate = len(successful_queries) / query_count * 100

        logger().info(f"SNTP Multiple Query Results:")
        logger().info(f"  Total Queries: {query_count}")
        logger().info(f"  Successful: {len(successful_queries)}")
        logger().info(f"  Success Rate: {success_rate:.1f}%")

        # Assert that at least 2 out of 3 queries succeeded (66% success rate)
        assert success_rate >= 66.0, f"SNTP multiple query test failed - success rate {success_rate:.1f}% below 66% threshold"
        assert len(successful_queries) >= 2, f"At least 2 queries should succeed, got {len(successful_queries)}"

        logger().info(f"✓ SNTP multiple query test completed successfully")

        # Stop sniffer if it was started
        if wifi_sniffer:
            logger().info("Stopping sniffer")
            wifi_sniffer.interfaces.capture.stop_capture()

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION_KEY --> {decryption_key}")
        logger().info("SSL Packet Decryption is going to start, This may take some time")
        ntp_capture_list = \
            zephyr_wifi_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["ntp"],
                                                          test_name, ap_mac_address)['ntp']
        assert len(ntp_capture_list), (f"NTP packets are not captured or one of the 4-way handshake packets are not "
                                       f"captured in the sniffer capture")

    except Exception as e:
        logger().error(f"Test failed with exception: {str(e)}")
        # Attempt to close SNTP context
        try:
            wifi_dut.interfaces.wifi.sntp_close(timeout=10)
        except:
            pass
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_dns_c19347(
        sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections, wifi_sniffer, request,
        remote_socket, wifi_client):
    """This test case verifies dns functionality"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections, test_name=test_name,
                                     sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        status, data = wifi_dut.interfaces.wifi.dns_get_addr_info()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        if "DNS resolving finished" in data:
            if "DNS IPv4 address" in data:
                target_ip = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', data).group(1)
                test_result = wifi_thread.icmp_send_test(
                    target_ip=target_ip,
                    packet_count=100,
                    timeout_ms=1000,
                    success_threshold=80
                )
                # Assert test result
                assert test_result, "ICMP send test failed - success rate below 80% threshold"
            else:
                assert 1, "DNS query failed"

        else:
            assert 1, "DNS query failed"
            wifi_dut.interfaces.wifi.reset()


    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_igmp_ipv4_multicast_data_rx_c50002(
        sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections,
        wifi_sniffer, request, wifi_client, multicast_client, net_perf_client, protocol):
    """ The test case verifies receive functionality on multicast address"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name

        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # Get target IP (use gateway or client IP)
        target_ip = wifi_client.interfaces.wifi.get_ip_address() if wifi_client else None

        # Initialize WiFi connection thread
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
        )

        # Start WiFi connection
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        # Log MAC addresses for reference
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC ADDRESS: {ap_mac_address}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        timeout = 60

        (
            ip_version,
            ttl,
            multicast_mac,
            multicast_ip,
            device_port,
            server_port,
            buffer_length,
            no_of_pkts,
        ) = multicast_client.interfaces.multicast.multicast_params()
        logger().info(
            f"The MultiCast Client Info is : {ip_version}, {ttl}, {multicast_mac}, {multicast_ip}, {device_port}, {server_port}, {buffer_length}, {no_of_pkts}"
        )

        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.igmp_join(multicast_ip)

        net_perf_client.interfaces.net_perf.init_client(
            host_ip=host_ip,
            device_ip=multicast_ip,
            time_out=timeout,
            protocol=protocol,
            time_to_leave="32",
            bandwidth="1M",
            host_role="C",
            bind_address=host_ip,
        )
        logger().info(
            f"Host IP: {host_ip}, Dut IP: {wifi_thread.dut_addr['device_ip']}, Protocol: {protocol}"
        )
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** start listening  ******")
        status, data = wifi_dut.interfaces.wifi.iperf(
            family=1,
            transfer_type=2,
            protocol=17,
            local_port=net_perf_client.interfaces.net_perf.client_port,
            local_ip=multicast_ip,
            remote_ip=host_ip,
            remote_port=net_perf_client.interfaces.net_perf.client_port,
            size=1470,
            ttl=30,
            throughput_type=4,
            qos=0,
            async_socket=0,
        )

        logger().info(f"data----------> {data}")

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        wifi_dut.interfaces.wifi.igmp_leave(multicast_ip)

        # Stop sniffer if it was started
        if wifi_sniffer:
            logger().info("Stopping sniffer")
            wifi_sniffer.interfaces.capture.stop_capture()
        igmp_capture_list = wifi_thread.get_igmp_list(
            wifi_thread.dut_addr["dut_mac_address"],
            decryption_key,
            ["igmp"],
            capture_filename,
        )
        time.sleep(5)
        assert (
                len(igmp_capture_list) > 0
        ), "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"


    except Exception as e:
        logger().error(f"Test failed with exception: {str(e)}")
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_igmp_ipv4_multicast_data_rx_after_group_leave_c70002(
        sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections,
        wifi_sniffer, request, wifi_client, multicast_client, net_perf_client, protocol):
    """ This test case verifies receive functionality on multiple address after leaving the multicast group"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name

        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # Get target IP (use gateway or client IP)
        target_ip = wifi_client.interfaces.wifi.get_ip_address() if wifi_client else None

        # Initialize WiFi connection thread
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
        )

        # Start WiFi connection
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        # Log MAC addresses for reference
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC ADDRESS: {ap_mac_address}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        timeout = 60

        (
            ip_version,
            ttl,
            multicast_mac,
            multicast_ip,
            device_port,
            server_port,
            buffer_length,
            no_of_pkts,
        ) = multicast_client.interfaces.multicast.multicast_params()
        logger().info(
            f"The MultiCast Client Info is : {ip_version}, {ttl}, {multicast_mac}, {multicast_ip}, {device_port}, {server_port}, {buffer_length}, {no_of_pkts}"
        )
        multicast_ip = "239.192.200.10"
        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.igmp_join(multicast_ip)

        net_perf_client.interfaces.net_perf.init_client(
            host_ip=host_ip,
            device_ip=multicast_ip,
            time_out=timeout,
            protocol=protocol,
            time_to_leave="32",
            bandwidth="1M",
            host_role="C",
            bind_address=host_ip,
        )
        logger().info(
            f"Host IP: {host_ip}, Dut IP: {wifi_thread.dut_addr['device_ip']}, Protocol: {protocol}"
        )
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** start listening  ******")
        status, data = wifi_dut.interfaces.wifi.iperf(
            family=1,
            transfer_type=2,
            protocol=17,
            local_port=net_perf_client.interfaces.net_perf.client_port,
            local_ip=multicast_ip,
            remote_ip=host_ip,
            remote_port=net_perf_client.interfaces.net_perf.client_port,
            size=1470,
            ttl=30,
            throughput_type=4,
            qos=0,
            async_socket=0,
        )

        logger().info(f"data before multicast leave ----------> {data}")

        wifi_dut.interfaces.wifi.igmp_leave(multicast_ip)

        net_perf_client.interfaces.net_perf.init_client(
            host_ip=host_ip,
            device_ip=multicast_ip,
            time_out=timeout,
            protocol=protocol,
            time_to_leave="32",
            bandwidth="1M",
            host_role="C",
            bind_address=host_ip,
        )
        logger().info(
            f"Host IP: {host_ip}, Dut IP: {wifi_thread.dut_addr['device_ip']}, Protocol: {protocol}"
        )
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** start listening  ******")
        status, data = wifi_dut.interfaces.wifi.iperf(
            family=1,
            transfer_type=2,
            protocol=17,
            local_port=net_perf_client.interfaces.net_perf.client_port,
            local_ip=multicast_ip,
            remote_ip=host_ip,
            remote_port=net_perf_client.interfaces.net_perf.client_port,
            size=1470,
            ttl=30,
            throughput_type=4,
            qos=0,
            async_socket=0,
            expected_status=0x0007,
        )

        logger().info(f"data after multicast leave ----------> {data}")
        logger().info(f"DUT unable to receive the data after multicast group leave which is expected behavior")

        wifi_dut.interfaces.wifi.reset()

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        # Stop sniffer if it was started
        if wifi_sniffer:
            logger().info("Stopping sniffer")
            wifi_sniffer.interfaces.capture.stop_capture()
        igmp_capture_list = wifi_thread.get_igmp_list(
            wifi_thread.dut_addr["dut_mac_address"],
            decryption_key,
            ["igmp"],
            capture_filename,
        )
        time.sleep(5)
        assert (
                len(igmp_capture_list) > 0
        ), "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"


    except Exception as e:
        logger().error(f"Test failed with exception: {str(e)}")
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_qos0_connect_subscribe_publish_unsubscribe_ipv4_TC127757(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, zephyr_wifi_collections,
        sniffer_filter):
    """QOS0: Subscribe to MQTT server with TCP connection and publish data oversubscribed topic"""

    try:
        test_name = request.node.name
        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            mqtt_client=mqtt_client,
            mqtt_server=mqtt_server,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.subscribe_and_publish()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_qos1_connect_subscribe_publish_unsubscribe_ipv4_TC127757(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, zephyr_wifi_collections,
        sniffer_filter):
    """QOS1: Subscribe to MQTT server with TCP connection and publish data oversubscribed topic"""

    try:
        test_name = request.node.name
        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            mqtt_client=mqtt_client,
            mqtt_server=mqtt_server,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.subscribe_and_publish(qos=1)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_qos2_connect_subscribe_publish_unsubscribe_ipv4_TC127757(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, zephyr_wifi_collections,
        sniffer_filter):
    """QOS2: Subscribe to MQTT server with TCP connection and publish data oversubscribed topic"""

    try:
        test_name = request.node.name
        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            mqtt_client=mqtt_client,
            mqtt_server=mqtt_server,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.subscribe_and_publish(qos=2)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_check_keep_alive_0_ipv4_TC127757(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, zephyr_wifi_collections,
        sniffer_filter):
    """Verify MQTT keep-alive functionality when MQTT keep-alive time set to 0"""

    try:
        test_name = request.node.name
        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            mqtt_client=mqtt_client,
            mqtt_server=mqtt_server,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.subscribe_and_publish(keep_alive=0)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        time.sleep(1)
        timestamp = []

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        mac_address = wifi_dut.interfaces.wifi.get_mac_address()

        mqtt_capture_list = wifi_thread.get_mqtt_list(mac_address, decryption_key,
                                                      ["mqtt"], test_name)

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

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "unassociated"])
@pytest.mark.parametrize("keep_alive_time,idle_time", [(60, 240)])
def test_wifi_sdk_mqtt_check_keep_alive_60_ipv4_TC327757(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, request, zephyr_wifi_collections,
        sniffer_filter, keep_alive_time, idle_time):
    """Verify MQTT keep-alive functionality when MQTT keep-alive time set to 60"""

    try:
        test_name = request.node.name
        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            mqtt_client=mqtt_client,
            mqtt_server=mqtt_server,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.subscribe_and_publish(qos=1, keep_alive=keep_alive_time, check_keep_alive=1,
                                          idle_time=(idle_time * 1000))
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        time.sleep(1)
        timestamp = []
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        mqtt_capture_list = wifi_thread.get_mqtt_list(dut_mac_address, decryption_key, ["mqtt"],
                                                      test_name)
        if not len(mqtt_capture_list):
            logger().info(f"MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the "
                          f"sniffer file")
            assert 0, "MQTT packets are not captured or one of the 4-way handshake pkts are not captured in the sniffer " \
                      "file "
        for count in mqtt_capture_list:
            if "Ping Request" in count[0]:
                timestamp.append(count[1])

        if (not len(timestamp)) and (len(mqtt_capture_list)):
            logger().info(f"MQTT-ping packets are not captured in the sniffer")
            assert 0, "MQTT-ping packets are not captured in the sniffer"

        if len(timestamp):
            for count in range(0, len(timestamp) - 1):
                time_diff = float(timestamp[count + 1]) - float(timestamp[count])
                if time_diff > (4 + keep_alive_time):
                    logger().info(
                        f"MQTT-KEEP alive packets are not sending every {keep_alive_time}sec on {count + 1} time")
            logger().info(
                f"Number of MQTT-KEEP alive packets sent->{len(timestamp)} while the test has been running for "
                f"{idle_time} sec when keep alive time configured is {keep_alive_time}")

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_zephyr_websocket_tx_and_rx(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                         utf_constants,
                                         request, zephyr_wifi_collections, sniffer_filter, wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan alone mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Initiate ping from the dut
        4. Verify websocket connection and data transfer functionality
    """
    try:
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        test_name = request.node.name
        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            http_server=http_server,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.websocket_send_and_receive(port=80, server_ip=server_ip)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_zephyr_http_get(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                              utf_constants,
                              request, zephyr_wifi_collections, sniffer_filter, wifi_client, index_path, http_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan alone mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Initiate ping from the dut
        4. Verify HTTP get functionality
    """
    try:
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        test_name = request.node.name
        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            http_server=http_server,
            http_client=http_client
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.http_get_put_post(port=80, server_ip=server_ip, url="/" + index_path)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as Ex:

        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_zephyr_http_post(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                               utf_constants,
                               request, zephyr_wifi_collections, sniffer_filter, wifi_client, index_path, http_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan alone mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Initiate ping from the dut
        4. Verify HTTP post functionality
    """
    try:
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        test_name = "test_wifi_zephyr_http_post"
        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            http_server=http_server,
            http_client=http_client
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.http_get_put_post(port=80, server_ip=server_ip, url=index_path, method=ZephyrHttpMethods.POST,
                                      payload="http post data")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_zephyr_http_put(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                              utf_constants,
                              request, zephyr_wifi_collections, sniffer_filter, wifi_client, index_path, http_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan alone mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Initiate ping from the dut
        4. Verify HTTP PUT functionality
    """
    try:
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        test_name = "test_wifi_zephyr_http_put"
        # Configure sniffer if available
        if wifi_sniffer:
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            zephyr_wifi_collections=zephyr_wifi_collections,
            test_name=test_name,
            sniffer_filter=sniffer_filter,
            http_server=http_server,
            http_client=http_client
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.http_get_put_post(port=80, server_ip=server_ip, url=index_path, method=ZephyrHttpMethods.PUT,
                                      payload="http put data")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": 12345678})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_tcp_data_transfer_rejoin_c19354(wifi_sniffer, wifi_dut, wifi_access_point, request, zephyr_wifi_collections,
                                         sniffer_filter, remote_socket,
                                         wifi_client, switch):
    """ Verify TCP data transfer functionality while STA is in rejoin process"""
    try:
        port = 5001
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections, test_name=test_name,
                                     sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, remote_socket=remote_socket)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_turn_off_time = 10
        start_delay = 30
        thread = Thread(target=ap_switch, args=(switch, ap_turn_off_time, start_delay), )
        thread.start()
        socket_fd = wifi_thread.tcp_server_single_socket(port=port, server_ip=server_ip, data_length=100)
        if socket_fd != 0:
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_fd)
            logger().info(f"Stopping the Remote Socket Server")
            remote_socket.interfaces.socket.stop()
            logger().info("Stop sending data on DUT as rejoin is going, wait for 90 seconds")
            time.sleep(90)

        wifi_thread.tcp_server_single_socket(port=port, server_ip=server_ip, data_length=100)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        remote_socket.interfaces.socket.stop()
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
