import time
import pytest
import re
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xAwsQos,
    Si91xCertificateType,
    Si91xModuleType,
    Si91xCertIdentifier,
    Si91xBTFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Cipher,
    Si91xCryptoWrapMode,
    Si91xCryptoKeyType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)
import string
import random
from utf.utf_config import UtfConfig
from retry import retry
from random import randint
import time
from datetime import datetime
from utf.utils.thread_base import ThreadBase
from threading import Thread
from utf.utils import get_tls_certificate_dir
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.stopwatch import Stopwatch
from AWSIoTPythonSDK.core.protocol.internal.clients import ClientStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.socket import SOCKET_TYPE_TCP
from utf.utils import print_dict
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.cloud_connectivity.\
    test_azure_mqtt_sdk import Azure_Thread


"""The testcases added in this file run below test steps for DUT-Si91x
        1. Configuration of DUT in 2G/5G : BGN
        2. Load ssl certificates in the DUT
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Create a new TCP/IP socket over ssl 
        6. Bind the socket with DUT ip address
        7. Connect the client with server socket as specified port number.
        8. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
    setup requirement:
        1. DUT(Si91x)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""


def logger():
    return get_logger(__name__)


def text_generator(size=2000):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def wifi_dut_marker(oper_mode=0, coex_mode=0, ca_cert=None, client_cert=None, client_key=None, eap_cert=None,
                    tcpip_feat=0, ext_custom_feat=0, ext_tcpip_feat=0):
    """
    Common method to generate wifi_dut marker for pytest.mark.config decorator.
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072}},
        "oper_mode": Si91xOperatingMode.WiFiClient | oper_mode,
        "coex_mode": Si91xCoexMode.WLANOnly | coex_mode,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | tcpip_feat,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | ext_tcpip_feat,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | ext_custom_feat,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if client_cert:
        config["client_cert"] = client_cert

    if client_key:
        config["client_key"] = client_key
    if eap_cert:
        config["eap_cert"] = eap_cert
    return pytest.mark.config("wifi_dut", wifi=config)

class ConcurrentMode:
    def __init__(self):
        self.dut_ap_ip = None

    @staticmethod
    def connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, count=3, ping_count=10, dut_ip=None):
        ip_dict = {}
        connected = False
        for i in range(len(wifi_clients)):
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            if dut_ip is None:
                ip_dict['dut_ip'] = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            else:
                ip_dict['dut_ip'] = dut_ip
            logger().info(f"********* Dut as AP IP **********: {ip_dict['dut_ip']}")
            for retry_count in range(count):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{wifi_clients[i].name}' to DUT")
                    ip_dict[f'client{i + 1}_ip'] = wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client{i + 1}_ip: {ip_dict[f'client{i + 1}_ip']}")
                    rc, stdout, stderr = wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {ip_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except Exception as error:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT:\n{error}...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        return ip_dict

    @staticmethod
    def print_throughput(iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    @staticmethod
    @retry(Exception, delay=15, tries=3)
    def ping_from_wifi_client(wifi_client, dest_ip, ping_count=10):
        logger().info(f"Initiating wlan ping from client '{wifi_client.name}' to destination_ip:'{dest_ip}'")
        for count in range(3):
            try:
                rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ping -c {ping_count} {dest_ip}")
                assert rc == 0
                logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                return rc == 0
            except:
                time.sleep(10)

class SocketDataTransfer:
    """
    This class contains methods related to TCP and SSL Data transfer between remote server and DUT
    """

    def tcp_socket_rx(self, remote_socket_factory, index, no_of_pkts, data_size):
        data_length = 0
        index = index - 1
        logger().info(f"TCP Receiving data over socket id {index}")
        for count in range(0, no_of_pkts):
            data = remote_socket_factory.interfaces.socket.sockets[index].recv_data_tcp(data_size)
            data_length = data_length + len(data)
        logger().info(f"Total bytes received on socket id {index} -> {data_length} TCP")

    def ssl_socket_rx(self, ssl_server, sock_id, pkt_count, buffer_length):
        logger().info(f"SSL Receiving data over socket id {sock_id}")
        ssl_server.interfaces.ssl.data_receive(sock_id + 1, pkt_count, buffer_length, pkt_rcv_timeout=120)


class aws_publish_message_Thread(ThreadBase):
    """
    Thread to publish data from DUT to aws server on subscribed topic and QOS value
    """

    def __init__(self, wifi_dut, topic, message, qos):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.topic = topic
        self.message = message
        self.qos = qos

    def run(self):
        logger().info("Publishing aws message from DUT")
        msg_count = len(self.message)
        send_count = 0
        while 1:
            msg = self.message[send_count]
            logger().info(f"\nDUT publishing message{send_count + 1} on topic:'{self.topic}' \nQOS:'{self.qos}'"
                          f"\nMessage{send_count + 1} with length:'{len(msg)} bytes'\nMessage{send_count + 1} is:'{msg}'")
            AwsConnection().publish_from_dut(self.wifi_dut, self.topic, msg, qos=self.qos)
            send_count += 1
            time.sleep(2)
            if send_count == msg_count:
                break
        logger().info("aws_publish_message_thread completed")


class aws_receive_message_Thread(ThreadBase):
    """
    Thread to receive data from aws server on subscribed topic and QOS value.
    """

    def __init__(self, aws_iot_client, topic, message, qos):
        super().__init__()
        self.aws_iot_client = aws_iot_client
        self.topic = topic
        self.message = message
        self.qos = qos

    def run(self):
        msg_count = 0
        recv_count = 0
        while 1:
            logger().info("Receiving published aws message on aws_iot_client")
            time.sleep(10)
            recv_messages = self.aws_iot_client.interfaces.aws_iot.get_received_messages()
            logger().info(f"Received message{recv_count + 1} is: '{recv_messages[recv_count].payload.decode()}'")
            logger().info(f"Received message{recv_count + 1} topic is: '{recv_messages[recv_count].topic}'")
            logger().info(f"Received message{recv_count + 1} qos is: '{recv_messages[recv_count].qos}'")
            assert recv_messages[recv_count].payload.decode() == self.message[
                msg_count], "Received wrong message in aws_iot_client"
            assert recv_messages[recv_count].topic == self.topic, "Received wrong topic in aws_iot_client"
            assert recv_messages[recv_count].qos == self.qos, "Received wrong qos in aws_iot_client"
            msg_count += 1
            recv_count += 1
            if recv_count == len(self.message):
                break
        logger().info("aws_receive_message_thread completed")


class AwsConnection(ThreadBase):
    """
    Class to connect, subscribe, publish data from DUT/Raspi to AWS server.
    """

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None, test_name=None,
                 aws_iot_client=None, messages=None, topic=None, qos=Si91xAwsQos.QOS1, port=8883, negative_case=False,
                 test_case=None, sleep=None):
        super().__init__()
        self.client_id = None
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.test_case = test_case
        self.timeout = 120
        self.aws_iot_client = aws_iot_client
        self.messages = messages
        self.topic = topic
        self.qos = qos
        self.port = port
        self.sleep = sleep
        self.negative_case = negative_case

    @retry(Exception, delay=25, tries=3)
    def connect_to_aws_server_from_dut(self, wifi_dut=None, client_id=None, iscleansession=True, keep_alive=1200,
                                       timeout=120, isWillMsgPresent=None, expected_status=SLStatus.SL_STATUS_OK,
                                       port=8883, aws_iot_mqtt_rx_buf_len=1024):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param client_id: mqtt client id for aws connection.
        @param iscleansession: Boolean Value(True/False).
        @param keep_alive: Keep alive period
        @param timeout: Timeout value to wait until command to be executed successfully.
        @return: Boolean Value(True/False).
        :param port:
        :param isWillMsgPresent:
        :param expected_status:
        """
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.aws_iot_mqtt_init(client_id=client_id, iscleansession=iscleansession,
                                                   keep_alive_interval=keep_alive, timeout=timeout,
                                                   port=port, isWillMsgPresent=isWillMsgPresent,
                                                   )
        time.sleep(2)
        wifi_dut.interfaces.wifi.aws_iot_mqtt_connect(timeout=timeout, expected_status=expected_status)
        return True

    def run(self):
        self.client_id = self.test_name + '_client'
        self.topic = 'topic_' + self.test_name
        try:
            if self.messages is None:
                self.messages = []
                for i in range(10):
                    self.messages.append(text_generator(size=10))
                logger().info(f"Messages are:{self.messages}")

            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            self.wifi_dut.interfaces.wifi.aws_iot_mqtt_init(client_id=self.client_id)
            time.sleep(2)
            self.wifi_dut.interfaces.wifi.aws_iot_mqtt_connect(timeout=self.timeout)

            time.sleep(20)
            logger().info("Connecting to AWS server from DUT is successful")
            self.subscribe_from_dut(self.wifi_dut, self.topic, qos=self.qos)
            self.connect_to_aws_server_from_raspi(self.aws_iot_client)
            self.subscribe_from_raspi(self.aws_iot_client, self.topic, qos=self.qos)

            if self.test_name == 'test_wifi_sdk_c537911':
                logger().info(f"\nDUT is publishing message on topic:'{self.topic}' \nQOS:'{self.qos}'")
                self.wifi_dut.interfaces.wifi.aws_iot_mqtt_publish_more(topic_name=self.topic, qos=self.qos,
                                                                        payload=self.messages[0],
                                                                        timeout=120,
                                                                        expected_status=SLStatus.SL_STATUS_MQTT_TX_BUFFER_TOO_SHORT_ERROR
                                                                        )
                logger().info("\n\n *** Publishing status from DUT on topic is failed error -33 observed as per "
                              "expectation *** \n\n\n\n")

            else:
                for count, msg in enumerate(self.messages):
                    logger().info(
                        f"\nDUT is publishing message{count + 1} on topic:'{self.topic}' \nQOS:'{self.qos}'"
                        f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
                    self.publish_from_dut(self.wifi_dut, self.topic, msg, qos=self.qos,
                                          negative_case=self.negative_case)

                    if self.test_case == 687529:
                        time.sleep(self.sleep)
                    else:
                        time.sleep(3)
                self.validate_aws_messages_from_raspi(self.aws_iot_client, self.topic, self.qos, self.messages)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
            raise e

    @retry(Exception, delay=15, tries=5)
    def subscribe_from_dut(self, wifi_dut, topic, qos=Si91xAwsQos.QOS0, timeout=120):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param topic: Topic name to subscribe from DUT on AWS Server
        @param qos: QOS value to subscribe on aws topic(0/1)
        @param timeout: Timeout value to wait until command to be executed successfully.
        """
        logger().info(f"DUT is Subscribing on topic '{topic}' and QOS:'{qos}'")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_subscribe(topic_name=topic, qos=qos, timeout=timeout)

    @retry(Exception, delay=15, tries=1)
    def publish_from_dut(self, wifi_dut, topic, message, qos, timeout=120, negative_case=False):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param topic: Topic name to subscribe from DUT on AWS Server.
        @param message: Data to publish from DUT on subscribed topic.
        @param qos: QOS value to publish data on aws topic(0/1).
        @param timeout: Timeout value to wait until command to be executed successfully.
        @param negative_case: Boolean Value(True/False).
        """
        logger().info(f"\nDUT is publishing message on topic:'{topic}' \nQOS:'{qos}'")
        result = wifi_dut.interfaces.wifi.aws_iot_mqtt_publish(topic_name=topic, qos=qos, payload=message,
                                                               timeout=timeout,
                                                               negative_case=negative_case)
        if negative_case:
            return result

    @retry(Exception, delay=10, tries=3)
    def connect_to_aws_server_from_raspi(self, aws_iot_client):
        """
        @param aws_iot_client: Fixture parameter to issue command in Raspi.
        """
        logger().info("Connecting to aws server from aws_iot_client")
        aws_iot_client.interfaces.aws_iot.aws_iot_connect()
        time.sleep(5)
        status = aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, "Connecting to AWS server from aws_iot_client is failed"

    @retry(Exception, delay=10, tries=3)
    def subscribe_from_raspi(self, aws_iot_client, topic, qos=Si91xAwsQos.QOS0):
        """
        @param aws_iot_client: Fixture parameter to issue command in Raspi.
        @param topic: Topic name to subscribe from Raspi on AWS Server.
        @param qos: QOS value to subscribe on aws topic(0/1).
        """
        logger().info(f"\n\n *** aws_iot_client is Subscribing on topic '{topic}' and QOS:'{qos}'*** \n\n")
        aws_iot_client.interfaces.aws_iot.received_messages.clear()
        aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(topic, qos=qos)
        status = aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, f"Subscribe on topic:'{topic}' is failed from aws_iot_client"

    @retry(Exception, delay=5, tries=5)
    def publish_from_raspi(self, aws_iot_client, topic, message, qos=Si91xAwsQos.QOS0):
        """
        @param aws_iot_client: Fixture parameter to issue command in Raspi.
        @param topic: Topic name to subscribe from Raspi on AWS Server.
        @param message: Data to publish from Raspi on subscribed topic.
        @param qos: QOS value to subscribe on aws topic(0/1).
        """
        try:
            status = aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
            assert status == ClientStatus.STABLE, f"Publish on topic:'{topic}' is failed from aws_iot_client"
        except AssertionError:
            self.connect_to_aws_server_from_raspi(aws_iot_client)
        if isinstance(message, list):
            for i, msg in enumerate(message):
                logger().info(
                    f"\naws_iot_client publishing message{i + 1} on topic:'{topic}' \nQOS:'{qos}'"
                    f"\nMessage{i + 1} with length:'{len(msg)} bytes'\nMessage{i + 1} is:'{msg}'")
                aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic, msg, qos=qos)
                time.sleep(5)
        else:
            aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic, message, qos=qos)

    @staticmethod
    def receive_aws_messages_from_dut(wifi_dut, retries=3, wait_time=3, expected_status=SLStatus.SL_STATUS_OK):
        """
        @param expected_status:
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param retries: retry attempts to receive published message in DUT.
        @param wait_time: Wait time to receive published message in DUT.
        :param expected_msg:
        """
        for retry_count in range(retries):
            try:
                time.sleep(wait_time)
                recv_msg = wifi_dut.interfaces.wifi.aws_select_socket(expected_status=expected_status)
                logger().info(f"Received message from DUT is: '{recv_msg}'")
                assert len(recv_msg), "Failed to receive published message in DUT"
                return recv_msg[-1]
            except Exception as err:
                logger().warning(f"Failed to receive published message in DUT\n{err}")
                if "0x1" in str(err):
                    wifi_dut.interfaces.wifi.is_dut_bad_state = True
                    raise
                time.sleep(5)

    @staticmethod
    def validate_aws_messages_from_raspi(aws_iot_client, topic, qos, messages, topic_1=None, topic_2=None,
                                         wait_time=10):
        """
        Validates messages received on AWS IoT client from a Raspberry Pi.

        @param aws_iot_client: Fixture parameter to issue command in Raspi.
        @param topic: Topic name which is subscribed on AWS Server (used if topic_1 and topic_2 are not provided).
        @param qos: QOS value which is subscribed on AWS Server (0 or 1).
        @param messages: List of messages published on AWS topics.
        @param topic_1: Optional first topic name for alternating messages.
        @param topic_2: Optional second topic name for alternating messages.
        @param wait_time: Wait time value until data is received from AWS server.
        """
        logger().info("\n *** Validating received AWS messages ***")
        time.sleep(wait_time)

        # Retrieve received messages from AWS IoT client
        recv_messages = aws_iot_client.interfaces.aws_iot.get_received_messages()

        # Check if we received enough messages
        if len(recv_messages) < len(messages):
            logger().error(f"Expected {len(messages)} messages but only received {len(recv_messages)}")
            raise AssertionError(
                f"Message count mismatch: Expected {len(messages)} messages, "
                f"but only received {len(recv_messages)} messages"
            )

        # Validate each received message
        for count, msg in enumerate(messages):
            # Determine the expected topic based on the presence of topic_1 and topic_2
            if topic_1 is not None and topic_2 is not None:
                expected_topic = topic_1 if count % 2 == 0 else topic_2
            else:
                expected_topic = topic

            # Log details of the received message
            logger().info(f"Received message {count + 1} is: '{recv_messages[count].payload.decode()}'")
            logger().info(f"Received message {count + 1} topic is: '{recv_messages[count].topic}'")
            logger().info(f"Received message {count + 1} qos is: '{recv_messages[count].qos}'")

            # Validate the payload, topic, and QoS
            assert recv_messages[count].payload.decode() == messages[count], "Received wrong message in aws_iot_client"
            assert recv_messages[count].topic == expected_topic, "Received wrong topic in aws_iot_client"
            assert recv_messages[count].qos == qos, "Received wrong qos in aws_iot_client"

        logger().info("AWS messages validated successfully")

    def connect_disconnect_aws(self, wifi_dut, aws_iot_client, client_id, topic, messages, qos=Si91xAwsQos.QOS1):
        try:
            logger().info("Initiating aws connect from DUT")
            assert self.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
            logger().info("Connecting to AWS server is successful")
            self.subscribe_from_dut(wifi_dut, topic, qos)
            self.connect_to_aws_server_from_raspi(aws_iot_client)
            self.subscribe_from_raspi(aws_iot_client, topic, qos)

            for i, msg in enumerate(messages):
                logger().info(f"\nDUT is publishing message{i + 1} on topic:'{topic}' \nQOS:'{qos}'"
                              f"\nMessage{i + 1} with length:'{len(msg)} bytes'\nMessage{i + 1} is:'{msg}'")
                self.publish_from_dut(wifi_dut, topic, msg, qos)
                time.sleep(3)
            self.validate_aws_messages_from_raspi(aws_iot_client, topic, qos, messages)

            logger().info("DUT Unsubscribing from aws topic")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_unsubscribe(topic)
            return 1
        finally:
            logger().info("Initiating aws_iot_disconnect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
            time.sleep(20)
            logger().info("\n")

    def to_signed_32_bit(self, num):
        if num >= 2 ** 31:
            return num - 2 ** 32
        return num


class mqtt_sniffer_validation:
    @staticmethod
    def get_mqtt_list(wifi_sniffer, capture_filename, dut_mac_address, decryption_key, print_layers):
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
                        if re.search(".*Application Data Protocol: mqtt", mqtt_layer):
                            logger().info(
                                f"As per sniffer capture MQTT packets sent by DUT..{ta_address}  ->  {mqtt_layer}")
                            mqtt_capture_list.append(tuple([mqtt_layer, packet.sniff_timestamp]))
        logger().info(f"***** Inside mqtt_sniffer_validation mqtt_capture_list {mqtt_capture_list}")
        return mqtt_capture_list


class WLanJoinThread(ThreadBase):
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, ping_count=None, test_case=None,
                 sl_collections=None, sniffer_filter=None, power_save=None, ap_mac_address=None,
                 capture_filename=None, client_key=None, wifi_client=None, switch=None, ssl_server=None, eap_type=None,
                 aws_iot_client=None, messages=None, topic=None, qos=Si91xAwsQos.QOS0, port=8883):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ping_count = ping_count
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.sniffer_filter = sniffer_filter
        self.dut_addr = None
        self.power_save = power_save
        self.ap_mac_address = ap_mac_address
        self.capture_filename = capture_filename
        self.wifi_client = wifi_client
        self.switch = switch
        self.client_key = client_key
        self.ssl_server = ssl_server
        self.eap_type = eap_type
        self.timeout = 120
        self.aws_iot_client = aws_iot_client
        self.messages = messages
        self.topic = topic
        self.qos = qos
        self.port = port

    def run(self):
        try:
            logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            if self.client_key:
                if self.test_case == '1163608' or self.test_case == '1163614' or self.test_case == '1163624':
                    index = 0
                    for cert in self.client_key:
                        logger().info(f"Clearing client key at index {index}")
                        self.wifi_dut.interfaces.wifi.clear_certificate(
                            cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_CBC_WRAP,
                            cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START, cert_index=index)
                        logger().info(f"loading client key at index {index}")
                        self.sl_collections.load_tls_client_private_key(self.wifi_dut, cert_file=cert, cert_index=index)
                        index = index + 1
                elif self.test_case == '1163607' or self.test_case == '1163615' or self.test_case == '1163621' \
                        or self.test_case == 719565:
                    index = 0
                    for cert in self.client_key:
                        logger().info(f"Clearing client key at index {index}")
                        self.wifi_dut.interfaces.wifi.clear_certificate(
                            cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                            cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START, cert_index=index)
                        logger().info(f"loading client key at index {index}")
                        self.sl_collections.load_tls_client_private_key(self.wifi_dut, cert_file=cert,
                                                                        cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                                                        wrap_iv_mode=Si91xCryptoWrapMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                                        iv=None,
                                                                        cert_index=index)
                        index = index + 1
                elif self.test_case == '1163604' or self.test_case == '1163606' or self.test_case == '719588':
                    self.wifi_dut.interfaces.wifi.clear_certificate(
                        cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_CBC_WRAP,
                        cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START)
                    self.sl_collections.load_tls_client_private_key(self.wifi_dut, cert_file=self.client_key)

                elif self.test_case == '1163619':
                    self.wifi_dut.interfaces.wifi.clear_certificate(
                        cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_CBC_WRAP,
                        cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START)
                    # self.sl_collections.load_tls_client_private_key(self.wifi_dut, cert_file=self.client_key)

                    cert_file = str(get_tls_certificate_dir().joinpath(self.client_key))
                    with open(cert_file) as f:
                        cert_contents = f.read()
                    size = len(cert_contents)

                    buffer_size = (512 * (int(size / 512))) + 512  # buffer_size should be more than size
                    address = self.wifi_dut.interfaces.wifi.allocate_memory(size=buffer_size)
                    self.wifi_dut.interfaces.wifi.load_memory(address, size=size, write_content=cert_contents)
                    data = self.wifi_dut.interfaces.wifi.generate_wrap_key(address=address,
                                                                           key_type=Si91xCryptoKeyType.SL_SI91X_TRANSPARENT_KEY,
                                                                           wrap_iv_mode=Si91xCryptoWrapMode.SL_SI91X_WRAP_IV_ECB_MODE)
                    data = data.decode()
                    pattern = r"wrapped_private_key_address:(0x[0-9A-Fa-f]+)|key_length:(\d+)"
                    # Find all matches using regular expression
                    matches = re.findall(pattern, data)
                    # Extract the address and key length from the matches
                    key_address = matches[0][0]  # The address will be the first element in the first tuple
                    length = matches[1][1]  # The key length will be the second element in the second tuple

                    self.wifi_dut.interfaces.wifi.load_private_wrap_key(address=key_address,
                                                                        cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_CBC_WRAP,
                                                                        cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                                        cert_index=0,
                                                                        iv="1234567890123456",
                                                                        cert_length=length)
                    self.wifi_dut.interfaces.wifi.memory_free(address)

                elif self.test_case == '769668':
                    self.wifi_dut.interfaces.wifi.clear_certificate(
                        cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_CBC_WRAP,
                        cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START)
                elif self.test_case == '719579':
                    self.wifi_dut.interfaces.wifi.clear_certificate(
                        cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_CBC_WRAP,
                        cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START)
                    # self.sl_collections.load_tls_client_private_key(self.wifi_dut, cert_file=self.client_key)

                    cert_file = str(get_tls_certificate_dir().joinpath(self.client_key))
                    with open(cert_file) as f:
                        cert_contents = f.read()
                    size = len(cert_contents)

                    buffer_size = (512 * (int(size / 512))) + 512  # buffer_size should be more than size
                    address = self.wifi_dut.interfaces.wifi.allocate_memory(size=buffer_size)
                    self.wifi_dut.interfaces.wifi.load_memory(address, size=size, write_content=cert_contents)
                    data = self.wifi_dut.interfaces.wifi.generate_wrap_key(address=address,
                                                                           key_type=Si91xCryptoKeyType.SL_SI91X_TRANSPARENT_KEY,
                                                                           wrap_iv_mode=Si91xCryptoWrapMode.SL_SI91X_WRAP_IV_CBC_MODE,
                                                                           iv="1234567890123457")
                    data = data.decode()
                    pattern = r"wrapped_private_key_address:(0x[0-9A-Fa-f]+)|key_length:(\d+)"
                    # Find all matches using regular expression
                    matches = re.findall(pattern, data)
                    # Extract the address and key length from the matches
                    key_address = matches[0][0]  # The address will be the first element in the first tuple
                    length = matches[1][1]  # The key length will be the second element in the second tuple

                    self.wifi_dut.interfaces.wifi.load_private_wrap_key(address=key_address,
                                                                        cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_CBC_WRAP,
                                                                        cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                                        cert_index=0,
                                                                        iv="1234567890123456",
                                                                        cert_length=length)
                    self.wifi_dut.interfaces.wifi.memory_free(address)

                elif self.test_case == '1163603' or self.test_case == '1163605' or self.test_case == '1163613' \
                        or self.test_case == '1163612' \
                        or self.test_case == '719581' or self.test_case == '719582' or self.test_case == '719577':
                    self.wifi_dut.interfaces.wifi.clear_certificate(
                        cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                        cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START)

                    self.sl_collections.load_tls_client_private_key(self.wifi_dut, cert_file=self.client_key,
                                                                    cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                                                    wrap_iv_mode=Si91xCryptoWrapMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                                    iv=None)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.capture_filename)
            if self.test_case == '1163612' or self.test_case == '1163615':
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type=self.eap_type,
                                                                        retry_count=3,
                                                                        ping_after_power_save=True)
            else:
                self.dut_addr = self.sl_collections. \
                    join_to_wifi_network_with_rejoin(wifi_dut=self.wifi_dut,
                                                     wifi_access_point=self.wifi_access_point,
                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                     retry_count=3,
                                                     rejoin_params=[0, 4, 40, 0])

            if self.test_case == '769669':
                self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                   psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                self.wifi_dut.interfaces.wifi.clear_certificate(
                    cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_CBC_WRAP,
                    cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START)
                self.sl_collections.load_tls_client_private_key(self.wifi_dut, cert_file=self.client_key)

            if self.test_case == '1163608' or self.test_case == '1163607' or self.test_case == '1163614' or \
                    self.test_case == '1163615' or self.test_case == '1163624' or self.test_case == '1163621' \
                    or self.test_case == 719565:
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                port2 = self.ssl_server.interfaces.ssl.config['device_port2']
                port3 = self.ssl_server.interfaces.ssl.config['device_port3']
                pkt_count = 100
                buffer_length = 1300
                if self.test_case == '1163621':
                    self.ssl_server.interfaces.ssl.start_server(port=port1,
                                                                server_cert='server_ecdsa_cert_test1.pem',
                                                                server_key='server_ecdsa_key_test1.pem',
                                                                tls_client_enable=True,
                                                                client_cert='ca_ecdsa_test1.pem')
                    self.ssl_server.interfaces.ssl.start_server(port=port2,
                                                                server_cert='server_ecdsa_cert_test2.pem',
                                                                server_key='server_ecdsa_key_test2.pem',
                                                                tls_client_enable=True,
                                                                client_cert='ca_ecdsa_test2.pem')
                    self.ssl_server.interfaces.ssl.start_server(port=port3,
                                                                server_cert='server_ecdsa_cert_test3.pem',
                                                                server_key='server_ecdsa_key_test3.pem',
                                                                tls_client_enable=True,
                                                                client_cert='ca_ecdsa_test3.pem')
                else:
                    self.ssl_server.interfaces.ssl.start_server(port=port1,
                                                                server_cert='server_test1.crt',
                                                                server_key='server_test1.key',
                                                                tls_client_enable=True,
                                                                client_cert='ca_test1.crt')
                    self.ssl_server.interfaces.ssl.start_server(port=port2,
                                                                server_cert='server_test2.crt',
                                                                server_key='server_test2.key',
                                                                tls_client_enable=True,
                                                                client_cert='ca_test2.crt')
                    self.ssl_server.interfaces.ssl.start_server(port=port3,
                                                                server_cert='server_test3.crt',
                                                                server_key='server_test3.key',
                                                                tls_client_enable=True,
                                                                client_cert='ca_test3.crt')

                server_ip = self.ssl_server.interfaces.ssl.server_ip
                device_ip = self.dut_addr['device_ip']

                for count in range(0, 3):
                    # Open ssl client socket in the DUT
                    sock = self.wifi_dut.interfaces.wifi.socket()
                    if count == 0:
                        assert sock == 0, "Socket id received is wrong. expected is 0"
                    elif count == 1:
                        assert sock == 1, "Socket id received is wrong. expected is 1"
                    else:
                        assert sock == 2, "Socket id received is wrong. expected is 2"
                    logger().info(
                        f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                    logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                    # Enable ssl option for socket opened
                    self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                    # self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="SOL_TCP", option_val="SO_MAX_RETRANSMISSION_TIMEOUT_VALUE")
                    if count == 0:
                        local_port = randint(5001, 6000)
                    elif count == 1:
                        local_port = randint(6001, 7000)
                    else:
                        local_port = randint(7001, 8000)
                    # Socket binds at (device_ip, 5001) in DUT
                    self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                                       timeout=15)
                    time.sleep(3)
                    try:
                        # ssl socket opened in DUT connects to the server
                        self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                       server_port=port1 + count)
                    except:
                        logger().info(f"Failed to connect to server socket")
                        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                        self.ssl_server.interfaces.ssl.stop_server()
                        time.sleep(1)
                        raise
                for socket in range(1, 4):
                    server_sock = socket
                    self.ssl_server.interfaces.ssl.data_receive(server_sock, pkt_count, buffer_length,
                                                                pkt_rcv_timeout=10)

                socket_list = self.wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7,
                                                                                       data_len=buffer_length,
                                                                                       number_of_pkts=pkt_count)
                sock_count = 0
                bytes_sent_list = []
                for socket_stats in socket_list:
                    logger.info(
                        f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
                    bytes_sent_list.append(socket_stats[0])
                    sock_count = sock_count + 1
                for socket in range(1, 4):
                    server_sock = socket
                    if self.ssl_server.interfaces.ssl.socket_connection_status(server_sock):
                        bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_sock)
                        assert bytes_sent_list[
                                   socket - 1] == bytes_received, f"Number of bytes sent by DUT and received on the " \
                                                                  f"remote peer not matched on socket {socket - 1}"
                for sock_id in range(3):
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
                    logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()

            elif self.test_case == '1163603' or self.test_case == '1163604' or self.test_case == '1163605' or self.test_case == '1163606' or self.test_case == '1163613' or self.test_case == '1163612' or self.test_case == '769669':
                pkt_count = 10000
                buffer_length = 1300
                self.ssl_server.interfaces.ssl.start_server(server_cert='server_test1.crt',
                                                            server_key='server_test1.key',
                                                            tls_client_enable=True, client_cert='ca_test1.crt')
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                device_ip = self.dut_addr['device_ip']
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                # Open ssl client socket in the DUT
                sock = self.wifi_dut.interfaces.wifi.socket()
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                # self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="SOL_TCP", option_val="SO_MAX_RETRANSMISSION_TIMEOUT_VALUE")
                local_port = randint(5001, 60000)
                # Socket binds at (device_ip, 5001) in DUT
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                                   timeout=15)
                time.sleep(3)
                try:
                    # ssl socket opened in DUT connects to the server
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                   server_port=port1)
                except:
                    logger().info(f"Failed to connect to server socket")
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                    self.ssl_server.interfaces.ssl.stop_server()
                    time.sleep(1)
                    raise
                # The api returns 100 bytes of random data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger().info(f"Sending data {data} over socket_no->{sock}")
                try:
                    self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
                except:
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                    self.ssl_server.interfaces.ssl.stop_server()
                    raise
                # SSL server receives the data over ssl socket
                time.sleep(1)
                server_socket_no = 1
                data_receive = self.ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
                logger().info(f"Data received on remote socket opened is {data_receive}")
                assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                logger().info("Data sent by DUT and received on server is matching\n\n")

                if self.ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                    self.ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
                result = self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count, server_ip)
                logger().info(f"Number of bytes sent by dut {result}")
                bytes_sent = result

                bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)

                logger().info(
                    f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")

                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                logger().info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()

            elif self.test_case == '719582':
                buffer_length = 1370
                # After association, start SSL server and measure RX throughput
                self.ssl_server.interfaces.ssl.start_server(
                    server_cert='server_test1.crt',
                    server_key='server_test1.key',
                    tls_client_enable=True,
                    client_cert='ca_test1.crt'
                )
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                device_ip = self.dut_addr['device_ip']
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']

                # Open SSL client socket in the DUT
                sock = self.wifi_dut.interfaces.wifi.async_sdk_socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                      protocol="IPPROTO_TCP")
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(sock,
                                                                   option_name="SL_SI91X_SO_HIGH_PERFORMANCE_SOCKET",
                                                                   cert_index=128)
                local_port = randint(5001, 60000)
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                                   timeout=15)
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1,
                                                               timeout=15)

                # RX throughput test: server sends, DUT receives
                socket_no = 1
                pkt_count = 10000
                duration = 60
                self.ssl_server.interfaces.ssl.send_data(socket_no, pkt_count, msg_length=buffer_length,
                                                         duration=duration)
                time.sleep(80)
                bytes_sent = self.ssl_server.interfaces.ssl.data_send_stats(socket_no)
                result = self.wifi_dut.interfaces.wifi.get_socket_rx_stats(sock, no_of_pkts="pkt_count", ttl=30)
                logger().info(f"*** result of rx_stats in wifidut {result}")
                bytes_received = int(result)
                logger().info(f"bytes sent by remote peer -> {bytes_sent}")
                logger().info(f"bytes received on socket {sock} -> {bytes_received}")
                logger().info(f"SSL rx throughput ->  {((bytes_received * 8) / (1000 * 1000 * duration))} Mbps")
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                logger().info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()
                time.sleep(5)
            elif self.test_case == '719581':
                self.ssl_server.interfaces.ssl.start_server(
                    server_cert='server_test1.crt',
                    server_key='server_test1.key',
                    tls_client_enable=True,
                    client_cert='ca_test1.crt'
                )

                buffer_length = 1370
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                device_ip = self.dut_addr['device_ip']
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                # Open ssl client socket in the DUT
                sock = self.wifi_dut.interfaces.wifi.socket()
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                local_port = randint(5001, 60000)
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip,
                                                   server_port=local_port,
                                                   timeout=15)
                time.sleep(3)
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                               server_port=port1)
                pkt_count = 10000
                time.sleep(1)
                server_socket_no = 1
                if self.ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                    self.ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
                result = self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
                logger().info(f"Number of bytes sent by dut {result}")
                bytes_sent = result
                bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
                logger().info(
                    f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                logger().info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()
                time.sleep(5)
            elif self.test_case == '1163619' or self.test_case == '719579' or self.test_case == '719588' or self.test_case == '769668':

                self.ssl_server.interfaces.ssl.start_server(server_cert='server_test1.crt',
                                                            server_key='server_test1.key',
                                                            tls_client_enable=True, client_cert='ca_test1.crt')
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                device_ip = self.dut_addr['device_ip']
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                # Open ssl client socket in the DUT
                sock = self.wifi_dut.interfaces.wifi.socket()
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                # self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="SOL_TCP", option_val="SO_MAX_RETRANSMISSION_TIMEOUT_VALUE")
                local_port = randint(5001, 60000)
                # Socket binds at (device_ip, 5001) in DUT
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                                   timeout=15)
                time.sleep(1)
                try:
                    # ssl socket opened in DUT connects to the server
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                   server_port=port1,
                                                                   expected_status=SLStatus.SL_STATUS_FAIL)
                except:
                    logger().info(
                        f"DUT is able to connect to TLS server when wrong cert is loaded which is not expected")
                    raise
                finally:
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                    self.ssl_server.interfaces.ssl.stop_server()
                    time.sleep(1)

            self.wifi_dut.interfaces.wifi.leave()
            logger().info("Stopping sniffer capture")
            self.wifi_sniffer.interfaces.capture.stop_capture()
            self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                filter_name="power_mgmt_bit")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=self.power_save_filter)['packet_count'] > 0, \
                "Unable to find NULL-Data frame packets with power save bit = 1"
            return

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

    def pdu_switch(self, sleep_time=10, switch=None):
        time.sleep(3)
        if not switch:
            logger().info("\n\nDisabling Wireless in AP")
            self.wifi_access_point.interfaces.wifi.stop_ap()
            time.sleep(sleep_time)
            logger().info("\n\nEnabling Wireless in AP")
            self.wifi_access_point.interfaces.wifi.start_ap()
            time.sleep(sleep_time)
            return
        logger().info("Turning off the AP")
        switch.interfaces.pdu_switch.turn_off()
        logger().info("Successfully powered off AP")
        time.sleep(sleep_time)
        logger().info("Again turning on the AP")
        switch.interfaces.pdu_switch.turn_on()

@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_cbc_mode_c1163604(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163604',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_mode_c1163603(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163603',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_cbc_mode_in_ram_c1163606(wifi_access_point, sniffer_filter,
                                                                        sl_collections,
                                                                        wifi_dut, ssl_server, utf_constants,
                                                                        wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163606',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_in_ram_c1163605(wifi_access_point, sniffer_filter, sl_collections,
                                                                   wifi_dut, ssl_server, utf_constants,
                                                                   wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163605',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sta_mode_ssid', "passphrase": '12345678', "security": 'WPA3',
                                               "protected_management_frame": "Capable", })
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_mode_wpa3_c1163613(wifi_access_point, sniffer_filter, sl_collections,
                                                                      wifi_dut, ssl_server, utf_constants,
                                                                      wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163613',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 eap_cert=["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
                 oper_mode=Si91xOperatingMode.EAPWiFiClient,
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_mode_eap_c1163612(wifi_access_point, sniffer_filter, sl_collections,
                                                                     wifi_dut, ssl_server, radius_server, utf_constants,
                                                                     wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163612',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server,
                                  eap_type="tls")

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=[("ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test2.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test3.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[("client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test2.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test3.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", [['client_test1.key', 'client_test2.key', 'client_test3.key']])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_cbc_mode_three_certs_c1163608(wifi_access_point, sniffer_filter,
                                                                             sl_collections,
                                                                             wifi_dut, ssl_server, utf_constants,
                                                                             wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163608',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=[("ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test2.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test3.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[("client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test2.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test3.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", [['client_test1.key', 'client_test2.key', 'client_test3.key']])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_mode_three_certs_c1163607(wifi_access_point, sniffer_filter,
                                                                             sl_collections,
                                                                             wifi_dut, ssl_server, utf_constants,
                                                                             wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163607',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=[("ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test2.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test3.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[("client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test2.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test3.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", [['client_test1.key', 'client_test2.key', 'client_test3.key']])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_cbc_mode_three_certs_in_ram_c1163614(wifi_access_point, sniffer_filter,
                                                                                    sl_collections,
                                                                                    wifi_dut, ssl_server, utf_constants,
                                                                                    wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163614',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=[("ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test2.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test3.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[("client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test2.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test3.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 eap_cert=["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
                 oper_mode=Si91xOperatingMode.EAPWiFiClient,
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", [['client_test1.key', 'client_test2.key', 'client_test3.key']])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_mode_three_certs_eap_sec_c1163615(wifi_access_point, sniffer_filter,
                                                                                     sl_collections,
                                                                                     wifi_dut, ssl_server,
                                                                                     utf_constants,
                                                                                     wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163615',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server,
                                  eap_type="tls")

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=[("ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test2.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test3.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[("client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test2.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test3.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 coex_mode=Si91xCoexMode.WLANOnly,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", [['client_test1.key', 'client_test2.key', 'client_test3.key']])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_cbc_mode_three_certs_SL_SI91X_EXT_FEAT_352K_M4SS_320K_sta_alone_c1163624(
        wifi_access_point, sniffer_filter, sl_collections,
        wifi_dut, ssl_server, utf_constants,
        wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163624',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=[("ca_ecdsa_test1.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_ecdsa_test2.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_ecdsa_test3.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[
                     ("client_ecdsa_cert_test1.pem", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                     ("client_ecdsa_cert_test2.pem", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                     ("client_ecdsa_cert_test3.pem", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key",
                         [['client_ecdsa_key_test1.pem', 'client_ecdsa_key_test2.pem', 'client_ecdsa_key_test3.pem']])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_mode_three_certs_ecdsa_c1163621(wifi_access_point, sniffer_filter,
                                                                                   sl_collections,
                                                                                   wifi_dut, ssl_server, utf_constants,
                                                                                   wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163621',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_neg_wrap_method_mismatch_c1163619(wifi_access_point, sniffer_filter, sl_collections,
                                                        wifi_dut, ssl_server, utf_constants,
                                                        wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163619',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
@pytest.mark.deployed_25q2
def test_wifi_sdk_ssl_neg_wrap_method_wrong_iv_c719579(wifi_access_point, sniffer_filter, sl_collections,
                                                       wifi_dut, ssl_server, utf_constants,
                                                       wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='719579',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test2.key'])
@pytest.mark.deployed_25q2
def test_wifi_sdk_ssl_neg_wrap_method_wrong_private_key_c719588(wifi_access_point, sniffer_filter, sl_collections,
                                                                wifi_dut, ssl_server, utf_constants,
                                                                wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='719588',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
@pytest.mark.deployed_25q2
def test_wifi_sdk_ssl_neg_without_loading_wrapped_private_key_c769668(wifi_access_point, sniffer_filter, sl_collections,
                                                                      wifi_dut, ssl_server, utf_constants,
                                                                      wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='769668',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
@pytest.mark.deployed_25q2
def test_wifi_sdk_ssl_load_wrapped_private_key_after_powersave_c769669(wifi_access_point, sniffer_filter,
                                                                       sl_collections,
                                                                       wifi_dut, ssl_server, utf_constants,
                                                                       wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='769669',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(
    ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
    tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
    ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_rx_throughput_private_wrap_key_iv_ecb_mode_c719582(wifi_access_point,
                                                                         sniffer_filter, sl_collections, wifi_dut,
                                                                         ssl_server, utf_constants, wifi_sniffer,
                                                                         client_key, request
                                                                         ):
    """
    Measure SSL RX throughput when private key is wrapped using SL_SI91X_WRAP_IV_ECB_MODE.
    """
    import time
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(
            wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='719582',
            ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
            capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(
    ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
    tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
    ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_tx_throughput_private_wrap_key_iv_ecb_mode_c719581(wifi_access_point, sniffer_filter,
                                                                         sl_collections, wifi_dut, ssl_server,
                                                                         utf_constants, wifi_sniffer,
                                                                         client_key, request
                                                                         ):
    """
    Measure SSL TX throughput when private key is wrapped using SL_SI91X_WRAP_IV_ECB_MODE.
    """
    import time
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(
            wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='719581',
            ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
            capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "bt_features": Si91xBTFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
@pytest.mark.parametrize("client_key", ['private-key.key'])
def test_wifi_sdk_aws_mqtt_connection_private_wrap_key_iv_ecb_mode_c719570(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                           sniffer_filter, client_key, sl_collections,
                                                                           aws_iot_client, utf_constants,
                                                                           ssl_server, request
                                                                           ):
    """
    Connect to AWS MQTT server when private key is wrapped using SL_SI91X_WRAP_IV_ECB_MODE.
    """
    client_id = 'client_c719570'
    topic = "topic_c719570"
    iterations = utf_constants.get('iter_count')
    import time
    capture_filename = request.node.name
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                               cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START)

    sl_collections.load_tls_client_private_key(wifi_dut, cert_file=client_key,
                                               cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                               wrap_iv_mode=Si91xCryptoWrapMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                               iv=None)
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        for iter_count in range(iterations):
            logger().info(f"Initiating aws test for iteration:{iter_count + 1}")
            messages = []
            for i in range(10):
                messages.append(text_generator(size=10))
            logger().info(f"Messages are:{messages}")
            ping_count = utf_constants.get("ping_count")
            result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
            dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            logger().info(f'AP BSSID = {ap_mac_address}')
            logger().info(f"Device mac address: {dut_mac_address}")
            aws_obj = AwsConnection()
            logger().info("Initiating aws connect from DUT")
            assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
            logger().info("Connecting to AWS server from DUT is successful")
            aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
            aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
            aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS1)

            for count, msg in enumerate(messages):
                logger().info(f"\nDUT is publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                              f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
                aws_obj.publish_from_dut(wifi_dut, topic, msg, qos=Si91xAwsQos.QOS1)
                time.sleep(3)
            aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic, Si91xAwsQos.QOS1, messages)

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac_address,
                                                   sniffer_filter)
            logger().info(f"Iteration '{iter_count + 1}' completed")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_1ssl_1tcp_sockets_send_data_testcase_c719574(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server,
                                                              remote_socket_factory, sl_collections,
                                                              request, client_key, sniffer_filter):
    """
    Connection to One TCP Server and One OpenSSL Server and transmit data over two sockets
    """

    capture_filename = request.node.name
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                               cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START)

    sl_collections.load_tls_client_private_key(wifi_dut, cert_file=client_key,
                                               cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                               wrap_iv_mode=Si91xCryptoWrapMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                               iv=None)
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        logger().info(f'AP BSSID = {ap_mac_address}')
        logger().info(f"Device mac address: {dut_mac_address}")
        sock_obj = SocketDataTransfer()
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = 5002
        list_sock = []
        # Open ssl server socket in remote device-Port1
        ssl_server.interfaces.ssl.start_server(
            port=port1,
            server_cert='server_test1.crt',
            server_key='server_test1.key',
            tls_client_enable=True,
            client_cert='ca_test1.crt'
        )
        server_ip = ssl_server.interfaces.ssl.server_ip

        # Only 1 SSL and 1 TCP socket
        # SSL socket (sock_count == 0)
        local_port_ssl = randint(5001, 20000)
        sock_ssl = wifi_dut.interfaces.wifi.socket()
        assert sock_ssl == 0, f"socket id received is wrong, expected is 0"
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock_ssl, option_name="TCP_ULP", option_val="tls_1_2")
        wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock_ssl, cert_index=0)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock_ssl, device_ip=dut_ip, server_port=local_port_ssl, timeout=15)
        retrial = 0
        for retry in range(3):
            try:
                logger().info(f"DUT with sock id {sock_ssl} connecting to server with port number:{port1}")
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock_ssl, server_ip=server_ip,
                                                          server_port=port1, timeout=20)
                retrial = 1
                break
            except:
                if retry == 2:
                    wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_ssl)
                    ssl_server.interfaces.ssl.stop_server()
                logger().info(f"Retrying connection for {retry} times")
                time.sleep(5)
        assert retrial == 1, "Connection to SSL socket failed"
        list_sock.append(sock_ssl)

        # TCP socket (sock_count == 1)
        local_port_tcp = randint(20001, 40000)
        server_socket = remote_socket_factory.interfaces.socket.create_socket()
        server_socket.time_limit = 3600
        server_socket.start_server(port=port2, socket_type=SOCKET_TYPE_TCP)
        sock_tcp = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP")
        assert sock_tcp == 1, f"socket id received is wrong, expected is 1"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock_tcp} which is expected")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock_tcp, device_ip=dut_ip, server_port=local_port_tcp, timeout=15)
        server_ipp = server_socket.hostname_or_ip_address(ip_version=4)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock_tcp, server_ip=server_ipp, server_port=port2)
        list_sock.append(sock_tcp)

        logger().info(f"SOCKET LIST{list_sock}")

        pkt_count = 100
        buffer_length = 100
        data_size = 100
        send_list = []

        for sock_id in list_sock:
            if sock_id == 1:
                th_start = Thread(target=sock_obj.tcp_socket_rx,
                                  args=(remote_socket_factory, sock_id, pkt_count, data_size, logger), )
            if sock_id == 0:
                th_start = Thread(target=sock_obj.ssl_socket_rx,
                                  args=(ssl_server, sock_id, pkt_count, buffer_length, logger), )
            send_list.append(th_start)
            th_start.start()

        wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=3, data_len=buffer_length,
                                                            number_of_pkts=pkt_count)
        time.sleep(10)
        validation = True
        for sock in list_sock:
            logger().info(f"Closing socket_id->{sock}")
            result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        ssl_server.interfaces.ssl.stop_server()
        remote_socket_factory.interfaces.socket.close_all()
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac_address,
                                               sniffer_filter)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"],
                                                               capture_filename, ap_mac_address)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        ssl_server.interfaces.ssl.stop_server()
        remote_socket_factory.interfaces.socket.close_all()
        wifi_dut.interfaces.wifi.leave()


@wifi_dut_marker(ca_cert=[("ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test2.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test3.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[("client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test2.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test3.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT |
                                Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", [['client_test1.key', 'client_test2.key', 'client_test3.key']])
def test_wifi_sdk_three_ssl_load_private_wrap_key_iv_ecb_mode_connect_close_sequence_c719853(wifi_access_point,
                                                                                             sniffer_filter,
                                                                                             sl_collections,
                                                                                             wifi_dut, ssl_server,
                                                                                             utf_constants,
                                                                                             wifi_sniffer,
                                                                                             request, client_key):
    """
    ssl client socket connection, data send and socket close regression for three SSL sockets
    """
    try:
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        test_run_time = utf_constants.get('time_duration')
        capture_filename = request.node.name
        channel = wifi_access_point.interfaces.wifi.channel
        index = 0
        for cert in client_key:
            logger().info(f"Clearing client key at index {index}")
            wifi_dut.interfaces.wifi.clear_certificate(
                cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START, cert_index=index)
            logger().info(f"loading client key at index {index}")
            sl_collections.load_tls_client_private_key(wifi_dut, cert_file=cert,
                                                       cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                                       wrap_iv_mode=Si91xCryptoWrapMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                       iv=None,
                                                       cert_index=index)
            index = index + 1
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        logger().info(f"Device mac address: {dut_mac_address}")

        fail_count = 0
        sw = Stopwatch()
        while sw.elapsed_sec < test_run_time:
            logger().info(
                f"\n\nRemaining time to complete this testcase is '{round(((test_run_time - sw.elapsed_sec) / 60), 2)}' minutes")
            # Open three ssl server sockets in remote device
            ssl_server.interfaces.ssl.start_server(
                port=port1,
                server_cert='server_test1.crt',
                server_key='server_test1.key',
                tls_client_enable=True,
                client_cert='ca_test1.crt'
            )
            ssl_server.interfaces.ssl.start_server(
                port=port2,
                server_cert='server_test2.crt',
                server_key='server_test2.key',
                tls_client_enable=True,
                client_cert='ca_test2.crt'
            )
            ssl_server.interfaces.ssl.start_server(
                port=port3,
                server_cert='server_test3.crt',
                server_key='server_test3.key',
                tls_client_enable=True,
                client_cert='ca_test3.crt'
            )

            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server(port=port1)
            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server(port=port2)
            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server(port=port3)
            server_ip = ssl_server.interfaces.ssl.server_ip

            # Open three ssl client sockets in the DUT
            socks = []
            ports = [port1, port2, port3]
            for i in range(3):
                pkt_count = 100
                buffer_length = 1300
                sock = wifi_dut.interfaces.wifi.socket()
                assert sock == i, f"Socket id received is wrong. expected is {i}"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                local_port = randint(5001, 60000)
                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_ip, server_port=local_port, timeout=15)
                time.sleep(1)
                try:
                    wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=ports[i])
                except:
                    fail_count = fail_count + 1
                    logger().info(f"Failed to connect to server socket {i}")
                    wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                    continue
                socks.append(sock)

            # The api returns 100 bytes of random data
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger().info(f"Sending data {data} over all sockets")

            sw1 = Stopwatch()
            while sw1.elapsed_sec <= 30:
                for idx, sock in enumerate(socks):
                    wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
                    time.sleep(1)
                    server_socket_no = idx + 1
                    data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
                    logger().info(f"Data received on remote socket {server_socket_no} is {data_receive}")
                    assert data == data_receive.decode(), f"Data sent by DUT and received on server {server_socket_no}" \
                                                          f" is not matching"
                    logger().info(f"Data sent by DUT and received on server {server_socket_no} is matching\n\n")

            for sock in socks:
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                logger().info(f"Successfully closed opened socket {sock} in the DUT")
            ssl_server.interfaces.ssl.stop_server()
            time.sleep(5)

        if fail_count:
            logger().info(f"{fail_count} times failed to connect to the server in '{test_run_time}' seconds of testrun")
        assert fail_count == 0, f"{fail_count} times failed to connect to the server in '{test_run_time}' " \
                                f"seconds of testrun"

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac_address,
                                               sniffer_filter)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_mac_address)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.SSL
        | Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.DHCPv4Server
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ca_cert": ["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "security": "WPA2",
        "channel": 11,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_SSL_CONCURRENT",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["init", "ap_enabled"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_private_key_wrap_ecb_mode_data_transfer_in_concurrent_mode_c719577(sniffer_filter, wifi_dut,
                                                                                         wifi_access_point, wifi_client,
                                                                                         sl_collections, ssl_server,
                                                                                         client_key, request,
                                                                                         wifi_sniffer):
    """Verify SSL data transfer on STA while DUT AP is active in concurrent mode."""
    socket_fd = None
    try:
        capture_filename = request.node.name
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                                   cert_identifier=Si91xCertIdentifier.
                                                   SL_NET_TLS_CLIENT_CREDENTIAL_START)

        sl_collections.load_tls_client_private_key(wifi_dut, cert_file=client_key,
                                                   cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                                   wrap_iv_mode=Si91xCryptoWrapMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                   iv=None)
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        con_obj = ConcurrentMode()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        logger().info(f"Device mac address: {dut_mac_address}")

        logger().info("Starting DUT as AP while STA remains associated")
        wifi_dut.interfaces.wifi.start_ap(
            ssid="TEST_SSL_CONCURRENT",
            security="WPA2",
            psk="Automation@123",
            channel=11,
            dtim_beacon_count="1",
            beacon_interval="100",
        )
        con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)

        port = 8443
        # Open ssl server socket in remote device-Port1
        ssl_server.interfaces.ssl.start_server(
            port=port,
            server_cert='server_test1.crt',
            server_key='server_test1.key',
            tls_client_enable=True,
            client_cert='ca_test1.crt'
        )
        server_ip = ssl_server.interfaces.ssl.server_ip
        time.sleep(3)

        socket_fd = wifi_dut.interfaces.wifi.async_sdk_socket(
            domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP"
        )
        assert socket_fd == 0, f"Socket id received is wrong: {socket_fd}, expected 0"

        wifi_dut.interfaces.wifi.bsdSetSocketOpt(
            socket_fd, option_name="TCP_ULP", option_val="tls_1_2"
        )
        time.sleep(2)

        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_fd,
            device_ip=dut_ip,
            server_port=local_port,
            timeout=15,
        )
        wifi_dut.interfaces.wifi.bsdSocketConnect(
            socket_fd=socket_fd,
            server_ip=server_ip,
            server_port=port,
            timeout=20,
        )

        socket_no = 1
        pkt_count = 3000
        buffer_len = 1200
        duration = 20
        ssl_server.interfaces.ssl.send_data(
            socket_no, pkt_count, msg_length=buffer_len, duration=duration
        )

        bytes_sent = 0
        # send_data is asynchronous on ssl_server; poll until stats are updated.
        for _ in range(10):
            time.sleep(3)
            try:
                bytes_sent = ssl_server.interfaces.ssl.data_send_stats(socket_no)
            except KeyError:
                continue
            if bytes_sent > 0:
                break

        bytes_received = int(
            wifi_dut.interfaces.wifi.get_socket_rx_stats(
                socket_fd, no_of_pkts="pkt_count", ttl=30
            )
        )

        logger().info(f"SSL bytes sent by remote peer: {bytes_sent}")
        logger().info(f"SSL bytes received on DUT STA socket: {bytes_received}")

        assert bytes_sent > 0, "SSL server did not report transmitted bytes"
        assert bytes_received > 0, "No SSL payload received on DUT STA socket"

        dut_ap_ip = wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
        assert con_obj.ping_from_wifi_client(
            wifi_client, dut_ap_ip, ping_count=10
        ), "AP-side client ping failed after SSL transfer"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        if socket_fd is not None:
            try:
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_fd)
            except Exception:
                pass
        try:
            ssl_server.interfaces.ssl.stop_server()
        except Exception:
            pass
        try:
            wifi_dut.interfaces.wifi.stop_ap()
        except Exception:
            pass

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "bt_features": Si91xBTFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["mydevkitcertificate.pem", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.parametrize("client_key", ['mydevkitkey.pem'])
def test_wifi_sdk_azure_mqtt_ssl_private_wrap_key_ecb_mode_c719571(wifi_access_point, wifi_dut, wifi_sniffer,
                                                                   azure_iot_client, sl_collections, wifi_client,
                                                                   request, utf_constants, sniffer_filter,
                                                                   client_key):
    """
    Test Description:
    This test case verifies the Azure MQTT functionality with TLS Wrap Key.
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START)

        sl_collections.load_tls_client_private_key(wifi_dut, cert_file=client_key,
                                                   cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                                   wrap_iv_mode=Si91xCryptoWrapMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                   iv=None)
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        iter_count = utf_constants.get("iter_count")
        azure_obj = Azure_Thread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            test_case=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            azure_iot_client=azure_iot_client,
            device_id="symmetric_device",
        )

        message = text_generator(size=10)
        logger().info(f"Message is:{message}")
        azure_obj.join_to_ap()
        azure_obj.connect_socket()
        azure_obj.azure_iot_init()
        azure_obj.subscribe_from_dut()
        azure_obj.send_msg_from_device(message=message)
        azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()

        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        azure_iot_client.interfaces.device.disconnect()

@wifi_dut_marker(
    ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
    tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
    ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_private_key_wrap_ecb_rx_while_rejoining_c719565(switch, wifi_dut, wifi_access_point,
                                                                      wifi_sniffer, ssl_server, sl_collections,
                                                                      sniffer_filter, client_key, request):
    """
    To check SSL rx functionality of DUT while rejoining
    """
    try:
        capture_filename = request.node.name
        tx_buffer_len = ssl_server.interfaces.ssl.config['buffer_length']
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START)

        sl_collections.load_tls_client_private_key(wifi_dut, cert_file=client_key,
                                                   cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                                   wrap_iv_mode=Si91xCryptoWrapMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                   iv=None)
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        logger().info(f"Device mac address: {dut_mac_address}")
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(
            port=port1,
            server_cert='server_test1.crt',
            server_key='server_test1.key',
            tls_client_enable=True,
            client_cert='ca_test1.crt'
        )
        server_ip = ssl_server.interfaces.ssl.server_ip
        time.sleep(3)

        socket_fd = wifi_dut.interfaces.wifi.async_sdk_socket(
            domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP"
        )
        assert socket_fd == 0, f"Socket id received is wrong: {socket_fd}, expected 0"

        wifi_dut.interfaces.wifi.bsdSetSocketOpt(
            socket_fd, option_name="TCP_ULP", option_val="tls_1_2"
        )
        time.sleep(2)

        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_fd,
            device_ip=dut_ip,
            server_port=local_port,
            timeout=15,
        )
        wifi_dut.interfaces.wifi.bsdSocketConnect(
            socket_fd=socket_fd,
            server_ip=server_ip,
            server_port=port1,
            timeout=20,
        )
        for tx_buffer in [tx_buffer_len, 20]:
            logger().info(f"\n************** Sending data from DUT with data size {tx_buffer} bytes **************")
            for pkt_count in range(8):
                if pkt_count == 4:
                    WLanJoinThread.pdu_switch(10, switch)
                    time.sleep(60)
                ssl_server.interfaces.ssl.send_data(1, 1, msg_length=tx_buffer)
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                rx_buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_fd, async_timeout=120,
                                                                          timeout=120)
                assert rx_buffer, "Packet loss observed at receiver side"
            time.sleep(5)
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=0)
            logger().info("Successfully closed socket_id 0 in the DUT")
            ssl_server.interfaces.ssl.stop_server()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac_address,
                                               sniffer_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)