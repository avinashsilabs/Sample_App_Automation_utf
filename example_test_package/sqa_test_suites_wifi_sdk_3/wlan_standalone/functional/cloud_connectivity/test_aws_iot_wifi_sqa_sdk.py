import filecmp
import os
import random
import re
import string
import time
from datetime import datetime
from retry import retry
import pytest
from threading import Thread
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
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
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes, Si91xOperatingMode, Si91xJoinFeatureBitMap
)
from AWSIoTPythonSDK.core.protocol.internal.clients import ClientStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import uuid
from utf_wiseconnect_3.tests.sl_status import SLStatus
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.http_https.test_http_https_get_post_sdk import ThreadSocketDataTransfer

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Connect to the AWS MQTT server
        5. Send or receive data on MQTT and verify packet loss tests 
    setup requirement:
        1. DUT(Si911x)
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
    Reported by cg team : rashmi & team
"""


def logger():
    return get_logger(__name__)


def text_generator(size=2000):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


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
                                       timeout=120, isWillMsgPresent="false", expected_status=SLStatus.SL_STATUS_OK,
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
                result = self.publish_from_dut(self.wifi_dut, self.topic, self.messages[0], qos=self.qos,
                                               negative_case=True)
                logger().info(f"Result of publish from DUT is: {result}")
                if result == 0xffffffdf:
                    logger().info("\n\n *** Publishing status from DUT on topic is failed error -33 observed as per "
                                  "expectation *** \n\n\n\n")
                    return True

            else:
                for count, msg in enumerate(self.messages):
                    logger().info(
                        f"\nDUT is publishing message{count + 1} on topic:'{self.topic}' \nQOS:'{self.qos}'"
                        f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
                    self.publish_from_dut(self.wifi_dut, self.topic, msg, qos=self.qos, negative_case=self.negative_case)

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
                logger().info(f"Received message from DUT is: '{recv_msg[-1].payload.decode()}'")
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


@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_connect_sub_publish_c19548(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                 sniffer_filter, sl_collections, aws_iot_client, utf_constants):
    """
    Connect to AWS MQTT server subscribe to topic and publish message on the same topic. Initiate disconnection and
    check the connection stability.
    """
    client_id = 'client_c19548'
    topic = "topic_c19548"
    iterations = utf_constants.get('iter_count')
    try:
        for iter_count in range(iterations):
            logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
            messages = []
            for i in range(10):
                messages.append(text_generator(size=10))
            logger.info(f"Messages are:{messages}")

            capture_filename = "test_wifi_sdk_C19548"
            channel = wifi_access_point.interfaces.wifi.channel
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
            result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
            dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger.info(f'AP BSSID = {ap_bssid}')
            logger.info(f"Device mac address: {dut_mac_address}")

            aws_obj = AwsConnection()
            logger.info("Initiating aws connect from DUT")
            assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
            logger.info("Connecting to AWS server from DUT is successful")
            aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS0)
            aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
            aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS0)

            for count, msg in enumerate(messages):
                logger.info(f"\nDUT is publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS0}'"
                            f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
                aws_obj.publish_from_dut(wifi_dut, topic, msg, qos=Si91xAwsQos.QOS0)
                time.sleep(3)
            aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic, Si91xAwsQos.QOS0, messages)

            logger.info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                                   sniffer_filter)
            logger.info(f"Iteration '{iter_count + 1}' completed")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 2})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_publish_message_in_thread1_and_receive_message_in_thread2_c19566(wifi_sniffer,
                                                                                       sniffer_filter,
                                                                                       wifi_access_point,
                                                                                       wifi_dut, aws_iot_client,
                                                                                       logger, sl_collections):
    """
    Connect to AWS MQTT server Subscribe to the topic. Publish a message in one thread on the topic and receive a
    message in the second thread on the same topic
    """
    client_id = 'client_c19566'
    topic = "topic_c19566"
    try:
        messages = []
        for i in range(10):
            messages.append(text_generator(size=10))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_C19566"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS1)

        t1 = aws_publish_message_Thread(wifi_dut, topic, messages, qos=Si91xAwsQos.QOS1)
        t2 = aws_receive_message_Thread(aws_iot_client, topic, messages, qos=Si91xAwsQos.QOS1)

        logger.info("aws_publish_message_thread + aws_receive_message_thread execution starts....")
        t1.start()
        t2.start()

        t1.wait_for_exit(True)
        t2.wait_for_exit(True)

        logger.info("Unsubscribing from aws topic from aws_iot_client")
        aws_iot_client.interfaces.aws_iot.aws_iot_unsubscribe(topic)

        logger.info("Initiating aws_iot_disconnect from aws_iot_client")
        aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 3})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_tx_after_rejoin_qos0_C19555(switch, wifi_sniffer, wifi_access_point, wifi_dut,
                                                  sniffer_filter, logger, sl_collections, aws_iot_client):
    client_id = 'client_c19555'
    topic = "topic_c19555"
    try:
        messages = []
        for i in range(10):
            messages.append(text_generator(size=10))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_aws_tx_after_rejoin_qos0_C19555"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS0)
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS0)

        send_count = 0
        ap_power_off = 0
        while 1:
            if ap_power_off:
                logger.info("Turning off the AP")
                switch.interfaces.pdu_switch.turn_off(delay=20)
                # wifi_access_point.interfaces.wifi.stop_ap()
                # time.sleep(20)
                logger.info("Successfully powered off AP")

                logger.info("Again turning on the AP")
                switch.interfaces.pdu_switch.turn_on(delay=100)
                # wifi_access_point.interfaces.wifi.start_ap()
                # time.sleep(100)
                ap_power_off = 0
                logger.info("Successfully powered on AP")
                logger.info("Pinging to DUT to check rejoin process is completed or not")
                status = sl_collections.ping(dut_ip, 30, 5)
                assert status, "Pinging to DUT is failed, DUT not rejoined to AP"

            msg = messages[send_count]
            logger.info(f"\nDUT publishing message on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS0}'"
                        f"\nMessage with length:'{len(msg)} bytes'\nMessage is:'{msg}'")
            aws_obj.publish_from_dut(wifi_dut, topic, msg, qos=Si91xAwsQos.QOS0)
            time.sleep(5)
            send_count = send_count + 1
            if send_count == int(len(messages) / 4):
                ap_power_off = 1
            if send_count == int(len(messages)):
                break
        aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic, Si91xAwsQos.QOS0, messages)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_tx_after_rejoin_qos1_c19556(switch, wifi_sniffer, wifi_access_point, wifi_dut,
                                                  sniffer_filter, logger, sl_collections, aws_iot_client):
    client_id = 'client_c19556'
    topic = "topic_c19556"
    try:
        messages = []
        for i in range(20):
            messages.append(text_generator(size=10))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_aws_tx_after_rejoin_qos1_C19556"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS1)

        send_count = 0
        ap_power_off = 0
        while 1:
            if ap_power_off:
                logger.info("Turning off the AP")
                switch.interfaces.pdu_switch.turn_off(delay=20)
                # wifi_access_point.interfaces.wifi.stop_ap()
                # time.sleep(20)
                logger.info("Successfully powered off AP")

                logger.info("Again turning on the AP")
                switch.interfaces.pdu_switch.turn_on(delay=100)
                # wifi_access_point.interfaces.wifi.start_ap()
                # time.sleep(100)
                ap_power_off = 0
                logger.info("Successfully powered on AP")
                logger.info("Pinging to DUT to check rejoin process is completed or not")
                status = sl_collections.ping(dut_ip, 30, 5)
                assert status, "Pinging to DUT is failed, DUT not rejoined to AP"

            msg = messages[send_count]
            logger.info(f"\nDUT publishing message{send_count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                        f"\nMessage with length:'{len(msg)} bytes'\nMessage is:'{msg}'")
            aws_obj.publish_from_dut(wifi_dut, topic, msg, qos=Si91xAwsQos.QOS1)
            time.sleep(5)
            send_count = send_count + 1
            if send_count == int(len(messages) / 4):
                ap_power_off = 1
            if send_count == int(len(messages)):
                break
        aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic, Si91xAwsQos.QOS1, messages)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 5})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("iterations", [2])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_check_rejoin_failure_functionality_of_dut_c19549(wifi_sniffer, switch,
                                                                       sniffer_filter, sl_collections, aws_iot_client,
                                                                       logger, wifi_dut, wifi_access_point, iterations):
    client_id = 'client_c19549'
    topic = "topic_c19549"
    try:
        messages = []
        for i in range(5):
            messages.append(text_generator(size=10))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_C19549"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        for iteration in range(iterations):
            logger.info(f"Initiating test for iteration:'{iteration + 1}'")
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [10, 6, 40, 0],
                                                                     ping_after_ps=True)
            dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger.info(f'AP BSSID = {ap_bssid}')
            logger.info(f"Device mac address: {dut_mac_address}")
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger.info(f'AP BSSID = {ap_bssid}')

            aws_obj = AwsConnection()
            logger.info("Initiating aws connect from DUT")
            assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
            logger.info("Connecting to AWS server from DUT is successful")
            aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
            aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
            aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS1)

            for count, msg in enumerate(messages):
                logger.info(f"\nDUT publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                            f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
                aws_obj.publish_from_dut(wifi_dut, topic, msg, qos=Si91xAwsQos.QOS1)
                time.sleep(3)
            aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic, Si91xAwsQos.QOS1, messages)

            logger.info("Initiating aws_iot unsubscribe from DUT")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_unsubscribe(topic_name=topic)

            logger.info("Initiating aws_iot disconnect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()

            logger.info("\n\nTurning off the AP")
            switch.interfaces.pdu_switch.turn_off(delay=5)
            logger.info("Successfully powered off AP")

            # logger.info("\n\nDisabling Wireless in AP")
            # wifi_access_point.interfaces.wifi.stop_ap()
            # time.sleep(5)
            # logger.info("Disabled Wireless in AP")

            logger.info("Checking for rejoin fail event from dut, this may take some time....")
            sw = Stopwatch()
            rejoin_msg = 0
            while sw.elapsed_sec <= 300:
                events = wifi_dut.interfaces.wifi.get_async_events()
                rejoin_error_events = [event for event in events if
                                       event.event_type == AsyncEventIdentifiers.REJOIN_EVENT]
                if len(rejoin_error_events):
                    rejoin_msg = 1
                    break
            if not rejoin_msg:
                wifi_dut.interfaces.wifi.is_dut_bad_state = True
            assert rejoin_msg == 1, f"Rejoin Error not found from DUT even after AP is switched off for 300 seconds for iteration:'{iteration + 1}'"
            logger.info("Rejoin Error Received from DUT")

            logger.info("\n\nAgain turning on the AP")
            switch.interfaces.pdu_switch.turn_on(delay=60)
            logger.info("Successfully powered on AP")

            # logger.info("\n\nEnabling Wireless in AP")
            # wifi_access_point.interfaces.wifi.start_ap()
            # time.sleep(60)
            logger.info(f"Iteration '{iteration + 1}' completed")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 6})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("test_run_time", [1800])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_publish_a_message_on_the_topic_for_every_10_minutes_c19567(wifi_dut, logger,
                                                                                 sniffer_filter, wifi_sniffer,
                                                                                 wifi_access_point, aws_iot_client,
                                                                                 test_run_time, sl_collections):
    """
    Connect to AWS MQTT server. Subscribe to the topic. Move DUT to sleep. Wake up every 10 minutes and publish a
    message on the topic. Then go to sleep. Repeat the same test for 24 hours.
    """
    client_id = 'client_c19567'
    topic = "topic_c19567"
    try:
        messages = []
        for i in range(5):
            messages.append(text_generator(size=20))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_C19567"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS0)
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS0)

        sw = Stopwatch()
        count = 0
        while sw.elapsed_sec < test_run_time:
            for msg in messages:
                count += 1
                logger.info(f"\nDUT publishing message{count} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS0}'"
                            f"\nMessage{count} with length:'{len(msg)} bytes'\nMessage{count} is:'{msg}'")
                aws_obj.publish_from_dut(wifi_dut, topic, msg, qos=Si91xAwsQos.QOS0)
                time.sleep(3)
            aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic, Si91xAwsQos.QOS0, messages)
            logger.info("DUT is going to sleep for 10 minutes")
            time.sleep(600)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


# Jira: WIFI_BT_UTFHELP-3000 [aws_iot: Unable to publish message with size 1390 bytes]
@pytest.mark.config('wifi_access_point', wifi={"channel": 7})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_publish_data_with_different_length_c19553(wifi_sniffer, wifi_access_point,
                                                                wifi_dut, logger, sl_collections, aws_iot_client,
                                                                sniffer_filter):
    """
    Publish data oversubscribed topic with different lengths(1 byte, 10 bytes, 100 bytes, 512 bytes, 1000 bytes, 1390 bytes)
    """
    client_id = 'client_c19553'
    topic = "topic_c19553"
    try:
        messages = []
        # for size in (1, 10, 100, 512, 1000, 1390):
        for size in [1, 10, 100, 512, 1000]:
            messages.append(''.join(random.choice(string.ascii_uppercase) for _ in range(size)))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_aws_publish_data_with_different_length_TC19553"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS0)
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS0)
        received_messages = []
        for count, msg in enumerate(messages):
            logger.info(f"\nDUT publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS0}'"
                        f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_publish_more(topic, Si91xAwsQos.QOS0, msg)
            time.sleep(10)
            received = aws_iot_client.interfaces.aws_iot.get_received_messages()[-1]
            received_messages.append(received.payload.decode('latin-1'))

        for i, message in enumerate(messages):
            assert any(message in recv_msg for recv_msg in
                       received_messages), f"Raspi did not received published message{message} from DUT"
            logger.info(f"Received Message{i + 1}: {message} ")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 8})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
@pytest.mark.parametrize("test_run_time", [1800])
def test_wifi_sdk_aws_connect_disconnect_sequence_c19552(wifi_sniffer, wifi_access_point, wifi_dut,
                                                         logger, sl_collections, aws_iot_client, test_run_time,
                                                         sniffer_filter):
    """
    Connect to AWS MQTT server subscribe to topic publish the data on the topic unsubscribe the subscribed topic and
    disconnect to server. Repeat the above steps continuously in loop for 30 minutes
    """
    client_id = 'client_c19552'
    topic = "topic_c19552"
    expected_error_count = 2
    try:
        messages = []
        for i in range(5):
            messages.append(text_generator(size=20))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_c19552"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        sw = Stopwatch()
        error_count = 0
        success_count = 0
        logger.info(f"Running the aws connect and disconnect test for '{test_run_time}' seconds")
        aws_obj = AwsConnection()
        while sw.elapsed_sec <= test_run_time:
            time_left = int((test_run_time - sw.elapsed_sec) / 60)
            logger.info(f"Remaining time to complete test is '{time_left}' minutes")
            try:
                success_count = aws_obj.connect_disconnect_aws(wifi_dut, aws_iot_client, client_id, topic, messages)
                success_count += success_count
            except Exception as err:
                error_count += 1
                logger.error(str(err))
                if error_count > expected_error_count:
                    logger.error(
                        f"\n\n********** Observed error count '{error_count}' times which is more than expected"
                        f" error count '{expected_error_count}', Hence marking the testcase as fail **********")
                    break
        assert success_count, "Failed to connect/subscribe/publish from DUT"
        logger.info(f"Number of times aws_connect_disconnect failure in span of 30 minutes:'{error_count}'")
        assert error_count <= expected_error_count, f"aws connect_publish_disconnect_sequence failed more than '{expected_error_count}' times in 30 minutes of test run"

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 9})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_connection_when_client_id_is_null_c19558(wifi_sniffer, wifi_access_point,
                                                               wifi_dut, logger, sl_collections, sniffer_filter):
    """
    Verify AWS connection when "AWS_IOT_MQTT_CLIENT_ID" is NULL and clean session flag set to true
    """
    try:
        capture_filename = "test_aws_connection_when_client_id_is_null_C19558"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect with client_id 'null' and clean_session flag 'True'")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id='NULL',
                                                      iscleansession=True), "Failed to connect aws server from DUT"

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 10})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_tcp_shutdown_c19546(wifi_sniffer, wifi_access_point, wifi_dut, aws_iot_client,
                                          logger, sl_collections, sniffer_filter, utf_constants):
    """
    Connect to AWS MQTT server subscribe to any topic, Receive data on the subscribed topic. Close the TCP connection
    and check the Connection stability.
    """
    client_id = 'client_c19546'
    topic = "topic_c19546"
    iterations = utf_constants.get('iter_count')
    capture_filename = "check_dut_rx_aws"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
    dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    logger.info(f"Device mac address: {dut_mac_address}")
    try:
        for iter_count in range(iterations):
            logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
            messages = []
            for i in range(10):
                messages.append(text_generator(size=10))
            logger.info(f"Messages are:{messages}")

            aws_obj = AwsConnection()
            logger.info("Initiating aws connect from DUT")
            assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
            logger.info("Connecting to AWS server from DUT is successful")
            aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS0)
            aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
            time.sleep(5)

            for count, msg in enumerate(messages):
                logger.info(
                    f"Raspi is publishing message{count + 1} on topic:'{topic}'\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
                aws_obj.publish_from_raspi(aws_iot_client, topic, msg, qos=Si91xAwsQos.QOS0)
                recv_msg = aws_obj.receive_aws_messages_from_dut(wifi_dut)
                assert msg == recv_msg, "Failed to receive published message in DUT"
            logger.info("Successfully received all published messages\n")

            logger.info("Initiating AWS shutdown")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=0)
            logger.info("AWS shutdown success")
            wifi_dut.interfaces.wifi.aws_flags['connected'] = False
            logger.info(f"Iteration '{iter_count + 1}' completed")

        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


# Jira: WIFI_BT_UTFHELP-3100 [aws_iot: Unable to receive message with size more than 100 bytes]
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_receive_data_over_subscribed_topic_with_different_lengths_c19554(wifi_sniffer,
                                                                                       wifi_access_point, wifi_dut,
                                                                                       aws_iot_client, logger,
                                                                                       sl_collections, sniffer_filter):
    """
    Receive data over subscribed topic with different lengths(1,100 bytes,500 bytes, 1000 bytes,1390 bytes)
    """
    client_id = 'client_c19554'
    topic = "topic_c19554"
    try:
        messages = []
        # for size in (1, 10, 100, 512, 1000, 1390):
        for size in (1, 10, 100, 512, 1000):
            messages.append(''.join(random.choice(string.ascii_uppercase) for _ in range(size)))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_aws_receive_data_with_different_len_c19554"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
        time.sleep(5)
        for count, msg in enumerate(messages):
            logger.info(f"\naws_iot_client publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                        f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
            aws_obj.publish_from_raspi(aws_iot_client, topic, msg, qos=Si91xAwsQos.QOS1)
            recv_msg = aws_obj.receive_aws_messages_from_dut(wifi_dut)
            assert msg == recv_msg, f"Failed to receive published message{count + 1} in DUT"
            logger.info(f"Received message{count + 1}: '{recv_msg}'")
        logger.info("Successfully received all published messages\n")

        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_rx_over_subscribed_topic_after_rejoin_qos1_c19559(switch, wifi_sniffer, wifi_access_point,
                                                                        wifi_dut, aws_iot_client,
                                                                        logger, sl_collections, sniffer_filter):
    client_id = 'client_c19559'
    topic = "topic_c19559"
    try:
        messages = []
        for i in range(12):
            messages.append(text_generator(size=20))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_c19559"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
        time.sleep(5)
        send_count = 0
        ap_power_off = 0
        while 1:
            if ap_power_off:
                logger.info("Turning off the AP")
                switch.interfaces.pdu_switch.turn_off(delay=20)
                # wifi_access_point.interfaces.wifi.stop_ap()
                # time.sleep(20)
                logger.info("Successfully powered off AP")

                logger.info("Again turning on the AP")
                switch.interfaces.pdu_switch.turn_on(delay=100)
                # wifi_access_point.interfaces.wifi.start_ap()
                # time.sleep(100)
                logger.info("Successfully powered on AP")
                ap_power_off = 0
                logger.info("Pinging to DUT to check rejoin process is completed or not")
                status = sl_collections.ping(dut_ip, 30, 5)
                assert status, "Pinging to DUT is failed, DUT not rejoined to AP"
                wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
                aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
                aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)

            msg = messages[send_count]
            send_count = send_count + 1
            logger.info(f"\naws_iot_client publishing message{send_count} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                        f"\nMessage{send_count} with length:'{len(msg)} bytes'\nMessage{send_count} is:'{msg}'")
            aws_obj.publish_from_raspi(aws_iot_client, topic, msg, qos=Si91xAwsQos.QOS1)
            recv_msg = aws_obj.receive_aws_messages_from_dut(wifi_dut, wait_time=10)
            assert msg == recv_msg, f"Failed to receive published message{send_count} in DUT"
            logger.info(f"Received message{send_count}: '{recv_msg}'")
            if send_count == int(len(messages) / 2):
                ap_power_off = 1
            if send_count == int(len(messages)):
                break
        logger.info("Successfully received all published messages\n")

        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 5})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_receive_func_while_receiving_100_msgs_continuously_c19561(wifi_access_point,
                                                                                wifi_sniffer, sniffer_filter, logger,
                                                                                wifi_dut, aws_iot_client, utf_constants,
                                                                                sl_collections):
    """
    MQTT receive functionality while receiving 100 MQTT messages continuously each with MQTT data length 300 bytes
    """
    client_id = 'client_c19561'
    topic = "topic_c19561"
    try:
        iterations = utf_constants.get('iter_count')
        messages = []
        for i in range(100):
            messages.append(text_generator(size=300))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_receiving_100_messages_c19561"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
        wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
        time.sleep(5)

        received_messages = []
        for iter_count in range(iterations):
            logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
            rc = 0
            for i, msg in enumerate(messages):
                logger.info(
                    f"\naws_iot_client publishing message{i + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                    f"\nMessage{i + 1} with length:'{len(msg)} bytes'\nMessage{i + 1} is:'{msg}'")
                aws_obj.publish_from_raspi(aws_iot_client, topic, msg, qos=Si91xAwsQos.QOS1)
                recv_msg = aws_obj.receive_aws_messages_from_dut(wifi_dut)
                if recv_msg:
                    rc += 1
                    received_messages.append(recv_msg)
                    logger.info(f"Received message{rc}: '{recv_msg}'")
            count = len(received_messages)
            if count < 100:
                logger.warning(f"******* Received '{count}' messages out of {len(messages)} published messages *******")
            else:
                logger.info(f"************ Successfully received all {len(messages)} published messages ************\n")
            logger.info(f"Iteration '{iter_count + 1}' completed")

        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 3})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("total_bytes", [20])
@pytest.mark.config(
    "wifi_dut",
    wifi={"thread_config": {"wifi": {"count": 2, "stack_len": 2048}, }})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_receive_100_mqtt_messages_over_2_subscribed_topics_c19563(wifi_sniffer,
                                                                                wifi_access_point, sniffer_filter,
                                                                                wifi_dut, sl_collections,
                                                                                aws_iot_client, logger, total_bytes):
    """
    MQTT receive functionality over SSL while receiving 100 MQTT messages continuously each with MQTT data length 2048
    bytes over two subscribed topics, one with granted QOS 0 and another with granted QOS1 when RSA key size used is 2048 bit length
    """
    try:
        client_id = 'client_c19563'
        topic1 = "topic1_c19563"
        topic2 = "topic2_c19563"
        messages = []
        received_messages = []
        for i in range(100):
            messages.append(text_generator(size=total_bytes))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_C19563"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
        aws_obj.subscribe_from_dut(wifi_dut, topic1, qos=Si91xAwsQos.QOS0)
        aws_obj.subscribe_from_dut(wifi_dut, topic2, qos=Si91xAwsQos.QOS1)
        time.sleep(5)

        qos0_thread = Thread(target=aws_obj.publish_from_raspi,
                             args=(aws_iot_client, topic1, messages, Si91xAwsQos.QOS0))
        qos1_thread = Thread(target=aws_obj.publish_from_raspi,
                             args=(aws_iot_client, topic2, messages, Si91xAwsQos.QOS1))
        qos0_thread.start()
        qos1_thread.start()
        for _ in range(len(messages)):
            recv_msg = aws_obj.receive_aws_messages_from_dut(wifi_dut)
            if recv_msg:
                received_messages.append(recv_msg)
        qos0_thread.join()
        qos1_thread.join()

        count = len(received_messages)
        logger.info(f"******* Received '{count}' messages out of {len(messages)} published messages *******")
        assert count >= 50, f"Received less than 50 messages out of {len(messages)} published messages"

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("iterations", [1])
@pytest.mark.parametrize("publish_len, total_bytes", [(100, 102400)])  # 100 is max limit-file size(1024000)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_disconnect", "disassociated"])
def test_wifi_sdk_aws_data_integrity_check_after_sending_1mb_of_data_c19564(wifi_sniffer, logger,
                                                                            wifi_access_point, wifi_dut, sniffer_filter,
                                                                            aws_iot_client, sl_collections, publish_len,
                                                                            iterations, total_bytes):
    """
    Data integrity check after sending 1Mb of data over MQTT over SSL when RSA key size used is 2048 bits
    """
    client_id = 'client_c19563'
    topic = "topic_c19563"
    try:
        current_time = time.time()
        capture_filename = "test_wifi_sdk_c19564"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
        aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS0)
        time.sleep(5)

        data = text_generator(size=total_bytes)
        file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
        tx_file = "./reports/" + capture_filename + "_tx_file_" + file_time_stamp + ".txt"
        with open(tx_file, "w") as temp:
            temp.write(data)

        recv_messages = []
        for iter_count in range(iterations):
            logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
            with open(tx_file, "r") as temp:
                while 1:
                    data = temp.read(publish_len)
                    if data == '':
                        break
                    else:
                        logger.info(
                            f"\nDUT is publishing message on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS0}'"
                            f"\nMessage with length:'{len(data)} bytes'\nMessage is:'{data}'")
                        aws_obj.publish_from_dut(wifi_dut, topic, data, qos=Si91xAwsQos.QOS0)
                        time.sleep(3)
                        recv_messages.append(
                            aws_iot_client.interfaces.aws_iot.get_received_messages()[-1].payload.decode())

            logger.info("Validating 1mb of data by comparing tx_file an rx_file")
            file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
            rx_file = "./reports/" + capture_filename + f"_rx_file_{iter_count}" + file_time_stamp + ".txt"
            if len(recv_messages):
                with open(rx_file, "w") as recv:
                    for data in recv_messages:
                        recv.write(data)
            if not os.path.exists(rx_file):
                logger.info("No aws data received at receiver")
            result = filecmp.cmp(tx_file, rx_file, shallow=False)
            assert result, "Data loss observed, Contents of tx file and rx file not matched"
            logger.info("Contents of tx_file and rx_file are same")
            logger.info(f"Iteration '{iter_count + 1}' completed")

        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 5})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("iterations", [1])
@pytest.mark.parametrize("publish_len, total_bytes", [(1000, 102400)])  # 493 is max limit-file size(1024000)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_data_integrity_check_after_receiving_1mb_of_data_c19562(wifi_dut, sniffer_filter,
                                                                              wifi_sniffer, sl_collections, iterations,
                                                                              aws_iot_client, wifi_access_point,
                                                                              logger, publish_len, total_bytes):
    """
    Data integrity check After receiving 1Mb file over MQTT over SSL when RSA key size used is 2048 bit length
    """
    client_id = 'client_c19562'
    topic = "topic_c19562"
    try:
        current_time = time.time()
        capture_filename = "test_wifi_sdk_c19562"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS0)
        time.sleep(5)

        data = text_generator(size=total_bytes)
        file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
        tx_file = "./reports/" + capture_filename + "_tx_file_" + file_time_stamp + ".txt"
        with open(tx_file, "w") as temp:
            temp.write(data)

        received_messages = []
        for iter_count in range(iterations):
            logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
            with open(tx_file, "r") as temp:
                while 1:
                    data = temp.read(publish_len)
                    if data == '':
                        break
                    else:
                        logger.info(f"\naws_client publishing message on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS0}'"
                                    f"\nMessage with length:'{len(data)} bytes'\nMessage is:'{data}'")
                        aws_obj.publish_from_raspi(aws_iot_client, topic, data, qos=Si91xAwsQos.QOS0)
                        recv_msg = aws_obj.receive_aws_messages_from_dut(wifi_dut)
                        if recv_msg:
                            received_messages.append(recv_msg)

            logger.info("Validating 1mb of data by comparing tx_file and rx_file")
            file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
            rx_file = "./reports/" + capture_filename + f"_rx_file_{iter_count}" + file_time_stamp + ".txt"
            if len(received_messages):
                with open(rx_file, "w") as recv:
                    for data in received_messages:
                        recv.write(data)
            if not os.path.exists(rx_file):
                logger.info("No aws data received at receiver")
            result = filecmp.cmp(tx_file, rx_file, shallow=False)
            assert result, "Data loss observed, Contents of tx file and rx file not matched"
            logger.info("Contents of tx_file and rx_file are same")
            logger.info(f"Iteration '{iter_count + 1}' completed")

        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.skip("Testcase is not present in master project")
@pytest.mark.config('wifi_access_point', wifi={"channel": 6})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_connect_after_wifi_reconnection_c4053(wifi_sniffer, wifi_access_point, wifi_dut,
                                                            logger, sl_collections, aws_iot_client, sniffer_filter):
    """
    Connect to AWS MQTT server after connecting to AP second time, the first time connection is closed intentionally by
    DUT by executing disconnect command
    """

    client_id = 'client_c4053'
    topic = "topic_c4053"
    try:
        messages = []
        for i in range(10):
            messages.append(text_generator(size=10))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_C4053"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        logger.info("Joining to AP for first time")
        sl_collections.connect(wifi_dut, wifi_access_point, join_status=False, retry_count=3)
        time.sleep(10)
        logger.info("Initiating wifi leave for first time")
        wifi_dut.interfaces.wifi.leave()

        logger.info("Joining to AP for second time")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS1)

        for count, msg in enumerate(messages):
            logger.info(f"\nDUT publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                        f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
            aws_obj.publish_from_dut(wifi_dut, topic, msg, qos=Si91xAwsQos.QOS1)
            time.sleep(3)
        aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic, Si91xAwsQos.QOS1, messages)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.skip("Testcase is not present in master project")
@pytest.mark.config('wifi_access_point', wifi={"channel": 7})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_server_not_respond_c4062(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                               sl_collections, aws_iot_client, sniffer_filter):
    """
    DUT functionality when server doesn't respond to tcp connection request sent by DUT when DUT is trying to connect
    AWS MQTT server.
    """
    try:
        messages = []
        for i in range(10):
            messages.append(text_generator(size=10))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_C4062"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        error_code = None
        try:
            wifi_dut.interfaces.wifi.aws_iot_mqtt_init(hostname="www.google.com")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_connect()
        except Exception as error:
            error_match = re.search("status:(.*)", str(error))
            if error_match:
                error_code = error_match.group()
                logger.info(f"error_code: {error_code}")
        assert error_code, "Error code not received from DUT while connecting to aws_server"
        logger.info(
            "************** Error code received from DUT while connecting to server, which is expected as per the testcase **************")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


""" Below testcases needs rework and will be uncommented for next upcoming announcements """


# @pytest.mark.config('wifi_access_point', wifi={"channel": 3})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_mqtt_keep_alive_func_when_keep_alive_is_0_c19551(wifi_sniffer, wifi_access_point,
#                                                                        wifi_dut, logger, sniffer_filter, sl_collections,
#                                                                        aws_iot_client):
#     """
#     MQTT keep alive functionality when keep alive period is 0, Check in sniffer for the Keep Alive Packets.
#     DUT should not send any Keep alive packets as the configured value is Zero.
#     """
#     client_id = 'client_c19551'
#     topic = "topic_c19551"
#     try:
#         messages = []
#         for i in range(10):
#             messages.append(text_generator(size=10))
#         logger.info(f"Messages are:{messages}")
#
#         capture_filename = "test_wifi_sdk_c19551"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#
#         aws_obj = AwsConnection()
#         logger.info("Initiating aws connect from DUT")
#         assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id,
#                                                       keep_alive=0), "Failed to connect aws server from DUT"
#         logger.info("Connecting to AWS server from DUT is successful")
#         aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS0)
#         aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
#         aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS0)
#
#         for count, msg in enumerate(messages):
#             logger.info(f"\nDUT is publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS0}'"
#                         f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
#             aws_obj.publish_from_dut(wifi_dut, topic, msg, qos=Si91xAwsQos.QOS0)
#             time.sleep(3)
#         aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic, Si91xAwsQos.QOS0, messages)
#
#         logger.info(f"Waiting in idle state")
#         time.sleep(30)
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
#                                                sniffer_filter)
#
#         logger.info("*************** Checking for Keep Alive Packets in sniffer capture ***************")
#         timestamp = []
#         decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#         logger.info(f"***** decryption key is {decryption_key}")
#         mqtt_capture_list = mqtt_sniffer_validation().get_mqtt_list(wifi_sniffer, capture_filename, dut_mac_address,
#                                                                     decryption_key, ["tls"])
#
#         if not len(mqtt_capture_list):
#             logger.info(f"mqtt packets are not captured or one of the 4-way handshake pkts are not captured in the "
#                         f"sniffer file")
#             assert 0, "mqtt packets are not captured or one of the 4-way handshake pkts are not captured in the sniffer " \
#                       "file "
#         for count in mqtt_capture_list:
#             timestamp.append(count[1])
#         assert len(timestamp) == 0, f"DUT is sending mqtt keep alive packets even though feature is disabled"
#         logger.info("As per sniffer capture no mqtt keep alive packets  sent from DUT")
#         logger.info(f"mqtt_capture timestamp : {timestamp}")
#         keep_alive_diff = [float(timestamp[i + 1]) - float(timestamp[i]) for i in range(len(timestamp) - 1)]
#         logger.info(f"*** keep_alive_difference is {keep_alive_diff}")
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 4})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# @pytest.mark.parametrize("keep_alive", [60, 100, 180])
# def test_wifi_sdk_aws_mqtt_keep_alive_func_with_different_periods_c19550(wifi_sniffer,
#                                                                          wifi_access_point,
#                                                                          wifi_dut, logger, sniffer_filter,
#                                                                          sl_collections, aws_iot_client, keep_alive
#                                                                          , utf_constants):
#     """
#     MQTT keep alive functionality with different keep alive periods(Verified with 60 sec, 100 sec, 180 sec).
#     Check in sniffer for the Keep Alive Packets, Will get the PUSH ACK messages in sniffer captures.
#     """
#     client_id = 'client_c19550'
#     topic = "topic_c19550"
#     iterations = utf_constants.get('iter_count')
#     try:
#         for iter_count in range(iterations):
#             logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
#             messages = []
#             for i in range(10):
#                 messages.append(text_generator(size=10))
#             logger.info(f"Messages are:{messages}")
#
#             capture_filename = "test_wifi_sdk_c19550"
#             channel = wifi_access_point.interfaces.wifi.channel
#             wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#             wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#             result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0],
#                                                                      power_save=False)
#             mode = 'power_save_low_latency'
#             logger.info(f"....Applying performance profile mode '{mode}' with listen interval '{keep_alive}'")
#             wifi_dut.interfaces.wifi.set_performance_profile(mode, listen_interval=keep_alive)
#             wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
#                                                           psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
#             dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#             ap_bssid = wifi_access_point.interfaces.wifi.bssid
#             logger.info(f'AP BSSID = {ap_bssid}')
#             logger.info(f"Device mac address: {dut_mac_address}")
#
#             aws_obj = AwsConnection()
#             logger.info("Initiating aws connect from DUT")
#             assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id,
#                                                           keep_alive=keep_alive), "Failed to connect aws server from DUT"
#             logger.info("Connecting to AWS server from DUT is successful")
#             aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS0)
#             aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
#             aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS0)
#
#             for count, msg in enumerate(messages):
#                 logger.info(f"\nDUT is publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS0}'"
#                             f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
#                 aws_obj.publish_from_dut(wifi_dut, topic, msg, qos=Si91xAwsQos.QOS0)
#                 time.sleep(3)
#             aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic, Si91xAwsQos.QOS0, messages)
#
#             logger.info(f"Waiting in idle state for keep_alive time is {keep_alive}")
#             time.sleep(keep_alive + 20)
#             logger.info("Stop Sniffer finally")
#             wifi_sniffer.interfaces.capture.stop_capture()
#             sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
#                                                    sniffer_filter)
#
#             logger.info("*************** Checking for Keep Alive Packets in sniffer capture ***************")
#             timestamp = []
#             decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#             logger.info(f"***** decryption key is {decryption_key}")
#             mqtt_capture_list = mqtt_sniffer_validation().get_mqtt_list(wifi_sniffer, capture_filename, dut_mac_address,
#                                                                         decryption_key, ["tls"])
#             if not len(mqtt_capture_list):
#                 logger.info(f"mqtt packets are not captured or one of the 4-way handshake pkts are not captured in the "
#                             f"sniffer file")
#                 assert 0, "mqtt packets are not captured or one of the 4-way handshake pkts are not captured in the sniffer " \
#                           "file "
#             for count in mqtt_capture_list:
#                 timestamp.append(count[1])
#             # assert len(timestamp) == 0, f"DUT is sending mqtt keep alive packets even though feature is disabled"
#             # logger.info("As per sniffer capture no mqtt keep alive packets  sent from DUT")
#
#             logger.info(f"mqtt_capture timestamp : {timestamp}")
#             keep_alive_diff = [float(timestamp[i + 1]) - float(timestamp[i]) for i in range(len(timestamp) - 1)]
#             logger.info(f"*** keep_alive_difference is {keep_alive_diff}")
#             keep_alive_flag_lower_limit = keep_alive - 5
#             keep_alive_flag_upper_limit = keep_alive + 5
#             logger.info(f"keep alive upper limit for {keep_alive} is {keep_alive_flag_upper_limit}")
#             logger.info(f"keep alive lower limit for {keep_alive} is {keep_alive_flag_lower_limit}")
#             for i in keep_alive_diff:
#                 assert (
#                         keep_alive_flag_lower_limit <= i <= keep_alive_flag_upper_limit), f" Keep alive {keep_alive} not within range between {keep_alive_flag_lower_limit} and {keep_alive_flag_upper_limit}"
#             logger.info(f"keep alive within range")
#             logger.info(f"Iteration '{iter_count + 1}' completed")
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_internet_connection_disconntion_c537615(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                              sniffer_filter, sl_collections, aws_iot_client,
                                                              utf_constants):
    """
    QOS1: Verify MQTT functionality when internet cable unplugged from AP after successful connection with AWS server
     and data transfer is happening.
    """
    client_id = 'client_c537615'
    topic = "topic_c537615"
    iterations = utf_constants.get('iter_count')
    messages = []
    capture_filename = "test_wifi_sdk_c537615"
    flag = False

    # AP mac address is required to filter the sniffer packets
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')

    for i in range(5):
        messages.append(text_generator(size=10))
    logger.info(f"Messages are:{messages}")
    wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                  beacon_missed_count=40,
                                                                  first_time_retry_enable=0)

    try:
        for iter_count in range(iterations):
            logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
            channel = wifi_access_point.interfaces.wifi.channel
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
            result = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                         wifi_access_point=wifi_access_point,
                                                         associated=wifi_dut.interfaces.wifi.associated,
                                                         channel=wifi_access_point.interfaces.wifi.channel)
            dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            logger.info(f"Device mac address: {dut_mac_address}")

            aws_obj = AwsConnection()
            logger.info("Initiating aws connect from DUT")
            assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id, keep_alive=2000), \
                "Failed to connect aws server from DUT"
            time.sleep(10)
            logger.info("Connecting to AWS server from DUT is successful")
            aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
            aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
            aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS1)

            for count, msg in enumerate(messages):
                logger.info(f"\nDUT is publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                            f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")

                result = wifi_dut.interfaces.wifi.aws_iot_mqtt_publish(topic_name=topic, qos=Si91xAwsQos.QOS1,
                                                                       payload=msg, timeout=10,
                                                                       negative_case=True)
                logger.info(f"result is {result}")
                logger.info(f"result type is {type(result)}")
                if result == -1:
                    logger.info("\n\n *** DUT is not able to publish message as internet is unplugged *** \n\n")
                    break
                if not flag:
                    logger.info(f"\n\n *** Unplugging internet cable from AP *** \n\n")
                    wifi_access_point.interfaces.wifi.enable_block_all_devices_internet_access()
                    flag = True
                    logger.info(f"\n\n Sleep for 50 second \n\n")
                    time.sleep(50)
                time.sleep(2)
            logger.info(f"\n\n COUNT = {count+1}, len(messages) = {len(messages)}\n\n ")
            if count+1 == len(messages):
                logger.info("\n\n *** DUT is able to publish messages even after internet is unplugged *** \n\n")
                assert False, "DUT is able to publish messages even after internet is unplugged"

            logger.info("\n\n *** plugging internet cable from AP.... Now validating DUT is able to publish "
                        "messages again or not *** \n\n")

            wifi_access_point.interfaces.wifi.disable_block_all_devices_internet_access()
            logger.info(f"\n\n Sleep for 10 second \n\n")
            time.sleep(10)

            for count, msg in enumerate(messages):
                logger.info(f"\nDUT is publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                            f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
                aws_obj.publish_from_dut(wifi_dut, topic, msg, qos=Si91xAwsQos.QOS1)
                time.sleep(5)
            time.sleep(10)
            aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic, Si91xAwsQos.QOS1, messages, wait_time=20)

            logger.info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                                   sniffer_filter)
            logger.info(f"Iteration '{iter_count + 1}' completed")
            # disconnect from the AP
            wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_access_point.interfaces.wifi.disable_block_all_devices_internet_access()


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_internet_connection_disconnection_c537713(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                              sniffer_filter, sl_collections, aws_iot_client,
                                                              utf_constants):
    """
    QOS0: Verify MQTT functionality when internet cable unplugged from AP after successful connection with AWS server
    and data transfer is happening.
    """
    client_id = 'client_c537713'
    topic = "topic_c537713"
    iterations = utf_constants.get('iter_count')
    messages = []
    capture_filename = "test_wifi_sdk_c537713"
    flag = False

    # AP mac address is required to filter the sniffer packets
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')

    for i in range(5):
        messages.append(text_generator(size=10))
    logger.info(f"Messages are:{messages}")

    try:
        for iter_count in range(iterations):
            logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
            channel = wifi_access_point.interfaces.wifi.channel
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
            result = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                         wifi_access_point=wifi_access_point,
                                                         associated=wifi_dut.interfaces.wifi.associated,
                                                         channel=wifi_access_point.interfaces.wifi.channel)
            dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            logger.info(f"Device mac address: {dut_mac_address}")

            aws_obj = AwsConnection()

            logger.info("Initiating aws connect from DUT")
            aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
            time.sleep(20)
            logger.info("Connecting to AWS server from DUT is successful")
            aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS0)
            aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
            aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS0)

            for count, msg in enumerate(messages):
                logger.info(f"\nDUT is publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS0}'"
                            f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")

                result = wifi_dut.interfaces.wifi.aws_iot_mqtt_publish(topic_name=topic, qos=Si91xAwsQos.QOS0,
                                                                       payload=msg, timeout=10,
                                                                       negative_case=True)
                logger.info(f"result is {result}")
                logger.info(f"result type is {type(result)}")
                if result == -1:
                    logger.info("\n\n *** DUT is not able to publish message as internet is unplugged *** \n\n")
                    break
                if not flag:
                    logger.info(f"\n\n *** Unplugging internet cable from AP *** \n\n")
                    wifi_access_point.interfaces.wifi.enable_block_all_devices_internet_access()
                    flag = True
                    logger.info(f"\n\n Sleep for 50 second \n\n")
                    time.sleep(50)
                time.sleep(5)

            logger.info(f"\n\n COUNT = {count + 1}, len(messages) = {len(messages)}\n\n ")
            if count + 1 == len(messages):
                logger.info("\n\n *** DUT is able to publish messages even after internet is unplugged *** \n\n")
                assert False, "DUT is able to publish messages even after internet is unplugged"

            logger.info("\n\n *** plugging internet cable from AP.... Now validating DUT is able to publish "
                        "messages again or not *** \n\n")
            wifi_access_point.interfaces.wifi.disable_block_all_devices_internet_access()
            time.sleep(30)

            for count, msg in enumerate(messages):
                logger.info(f"\nDUT is publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS0}'"
                            f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
                aws_obj.publish_from_dut(wifi_dut, topic, msg, qos=Si91xAwsQos.QOS0)
                time.sleep(5)
            aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic, Si91xAwsQos.QOS0, messages)

            logger.info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                                   sniffer_filter)
            logger.info(f"Iteration '{iter_count + 1}' completed")
            wifi_dut.interfaces.wifi.leave()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_access_point.interfaces.wifi.disable_block_all_devices_internet_access()


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_connect_will_message_negative_c537896(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                            sniffer_filter, sl_collections, aws_iot_client,
                                                            utf_constants):
    """
    Negative case : Set Will message to TRUE and check for error message.
    """
    client_id = 'client_c537896'
    try:
        capture_filename = "test_wifi_sdk_c537896"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=wifi_access_point.interfaces.wifi.channel,
                                            power_save=False)

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut=wifi_dut, isWillMsgPresent="true", client_id=client_id,
                                                      expected_status=SLStatus.SL_STATUS_AWS_WILL_CONNECTION_FAILURE), "Failed to connect aws server " \
                                                                   "from DUT"
        logger.info("As per expectation connection to AWS server from DUT should be unsuccessful")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe",
                             "disassociated"])
def test_wifi_sdk_aws_change_port_number_negative_c537897(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                          sl_collections):
    """
    Negative case : Change port number to 9999 and check whether MQTT connection is happening or not
    """
    client_id = 'client_c537897'

    try:
        capture_filename = "test_wifi_sdk_C19548"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=wifi_access_point.interfaces.wifi.channel,
                                            power_save=False)

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut=wifi_dut, client_id=client_id, port=9999,
                                                      expected_status=SLStatus.SL_STATUS_AWS_CONNECTION_FAILURE,
                                                      timeout=20), "Failed to connect aws server " \
                                                                   "from DUT"
        logger.info("As per expectation connection to AWS server from DUT should be unsuccessful")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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


@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_connection_tcp_data_transfer_c537899(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                           sl_collections, aws_iot_client):
    """
     AWS MQTT one thread and TCP/UDP data transfer in another thread
    """
    try:
        test_name = "test_wifi_sdk_c537899"
        capture_filename = "test_wifi_sdk_c537899"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        conn_result = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                          wifi_access_point=wifi_access_point,
                                                          associated=wifi_dut.interfaces.wifi.associated,
                                                          channel=wifi_access_point.interfaces.wifi.channel,
                                                          power_save=False)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client)
        socket_thread = ThreadSocketDataTransfer(wifi_dut=wifi_dut, dut_ip=conn_result['device_ip'],
                                                 wifi_access_point=wifi_access_point)

        aws_obj.start()
        socket_thread.start()

        aws_obj.wait_for_exit()
        socket_thread.wait_for_exit()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_2000_bytes_rx_data_send_to_dut_c537910(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                             sl_collections, aws_iot_client):
    """
    Negative Case : Verify error -32 observed when 2000bytes of RX data sent to DUT
    """
    client_id = 'client_c537910'
    topic = "topic_c537910"

    try:
        capture_filename = "test_wifi_sdk_537910"
        messages = []
        for i in range(2):
            messages.append(text_generator(size=2000))
        logger.info(f"Messages are:{messages}")

        messages1 = []
        for i in range(2):
            messages1.append(text_generator(size=100))
        logger.info(f"Messages are:{messages1}")

        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=wifi_access_point.interfaces.wifi.channel,
                                            power_save=False)

        aws_obj = AwsConnection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut=wifi_dut, client_id=client_id,
                                                      timeout=20), "Failed to connect aws server " \
                                                                   "from DUT"

        time.sleep(20)
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS1)

        for i in range(0, 1):
            send_count = 0
            send_count = send_count + 1
            logger.info(f"\naws_iot_client publishing message{send_count} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                        f"\nMessage{send_count} with length:'{len(messages[i])} bytes'\nMessage{send_count} is:'{messages[i]}'")
            aws_obj.publish_from_raspi(aws_iot_client, topic, messages[i], qos=Si91xAwsQos.QOS1)
            time.sleep(10)
            error_code = aws_obj.publish_from_dut(wifi_dut, topic, messages1[i], qos=Si91xAwsQos.QOS1, negative_case=True)
            assert error_code == 4294967264, f"Failed to Verify error -32= {error_code}"
            signed_number = aws_obj.to_signed_32_bit(error_code)
            logger.info(f"Verify error -32 observed when 2000bytes of RX data sent to DUT and publish from DUT side ={signed_number}")


        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_2000_bytes_tx_data_send_to_dut_c537911(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                             sl_collections, aws_iot_client, utf_constants):
    """
    Negative Case : Verify error -33 observed when Tx buffer length is given as 10
    """
    iterations = utf_constants.get('iter_count')
    test_name = "test_wifi_sdk_c537911"

    try:
        capture_filename = "test_wifi_sdk_c537911"
        messages = []
        for i in range(1):
            messages.append(text_generator(size=2000))
        logger.info(f"Messages are:{messages}")

        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=wifi_access_point.interfaces.wifi.channel,
                                            power_save=False)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client, messages=messages, negative_case=True,
                                qos=Si91xAwsQos.QOS0)

        for i in range(iterations):
            logger.info(f"Initiating aws test for iteration:{i + 1}")
            aws_obj.start()
            aws_obj.wait_for_exit()

            logger.info("Initiating aws_iot_disconnect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
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
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_change_port_number_443_tx_c661500(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                     sl_collections, aws_iot_client, utf_constants):
    """
    Connect to AWS server with port 443 and check whether Tx functionality
    """
    iterations = utf_constants.get('iter_count')
    topic = "topic_c661500"
    test_name = "test_wifi_sdk_c661500"
    messages = []
    for i in range(10):
        messages.append(text_generator(size=100))
    logger.info(f"Messages are:{messages}")

    try:
        capture_filename = "test_wifi_sdk_c661500"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        assert (len(scan_results) >= 1), "Scan failed"
        logger.info(scan_results)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=0,
                                            power_save=False, skip_scan=False)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client, messages=messages)

        for i in range(iterations):
            logger.info(f"Initiating aws test for iteration:{i + 1}")
            aws_obj.start()
            aws_obj.wait_for_exit()

            logger.info("Initiating aws_iot_disconnect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
            time.sleep(20)
            logger.info("\n")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
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
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_change_port_number_443_rx_c661501(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                     sl_collections, aws_iot_client, utf_constants):
    """
    Connect to AWS server with port 443 and check whether Rx functionality
    """
    iterations = utf_constants.get('iter_count')
    topic = "topic_c661501"
    test_name = "test_wifi_sdk_c661501"
    client_id = 'client_c661501'
    messages = []
    for i in range(10):
        messages.append(text_generator(size=100))
    logger.info(f"Messages are:{messages}")

    try:
        capture_filename = "test_wifi_sdk_c661501"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        assert (len(scan_results) >= 1), "Scan failed"
        logger.info(scan_results)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=wifi_access_point.interfaces.wifi.channel,
                                            power_save=False, skip_scan=False)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client, messages=messages)

        for i in range(iterations):
            logger.info(f"Initiating aws test for iteration:{i + 1}")
            assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id, port=443), ("Failed to connect aws "
                                                                                           "server from DUT")
            logger.info("Connecting to AWS server from DUT is successful")
            aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
            aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
            wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
            time.sleep(5)

            received_messages = []
            for iter_count in range(iterations):
                logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
                rc = 0
                for i, msg in enumerate(messages):
                    logger.info(
                        f"\naws_iot_client publishing message{i + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                        f"\nMessage{i + 1} with length:'{len(msg)} bytes'\nMessage{i + 1} is:'{msg}'")
                    aws_obj.publish_from_raspi(aws_iot_client, topic, msg, qos=Si91xAwsQos.QOS1)
                    recv_msg = aws_obj.receive_aws_messages_from_dut(wifi_dut)
                    if recv_msg:
                        rc += 1
                        received_messages.append(recv_msg)
                        logger.info(f"Received message{rc}: '{recv_msg}'")
                count = len(received_messages)
                if count < 100:
                    logger.warning(
                        f"******* Received '{count}' messages out of {len(messages)} published messages *******")
                else:
                    logger.info(
                        f"************ Successfully received all {len(messages)} published messages ************\n")
                logger.info(f"Iteration '{iter_count + 1}' completed")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
def test_wifi_sdk_aws_wake_on_wireless_C537912(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                               sl_collections, aws_iot_client, utf_constants):
    """
    Connect to AWS server with port 443 and check whether Rx functionality
    """
    iterations = utf_constants.get('iter_count')
    topic_1 = "topic_1_c537912"
    topic_2 = "topic_2_c537912"
    test_name = "test_wifi_sdk_c537912"
    client_id = 'client_c537912'
    messages = []
    for i in range(10):
        messages.append(text_generator(size=100))
    logger.info(f"Messages are:{messages}")

    try:
        capture_filename = "test_wifi_sdk_c661501"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=wifi_access_point.interfaces.wifi.channel)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client, messages=messages)

        for i in range(iterations):
            logger.info(f"Initiating aws test for iteration:{i + 1}")
            assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), ("Failed to connect aws "
                                                                                 "server from DUT")
            logger.info("Connecting to AWS server from DUT is successful")
            aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
            aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=Si91xAwsQos.QOS1)
            aws_obj.subscribe_from_dut(wifi_dut, topic_2, qos=Si91xAwsQos.QOS1)
            aws_obj.subscribe_from_raspi(aws_iot_client, topic_1, qos=Si91xAwsQos.QOS1)
            aws_obj.subscribe_from_raspi(aws_iot_client, topic_2, qos=Si91xAwsQos.QOS1)
            wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
            time.sleep(5)

            received_messages = []
            for iter_count in range(iterations):
                logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
                rc = 0
                for i, msg in enumerate(messages):
                    logger.info(
                        f"\n aws_iot_client publishing message{i + 1} on topic:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS1}'"
                        f"\nMessage{i + 1} with length:'{len(msg)} bytes'\nMessage{i + 1} is:'{msg}'")
                    aws_obj.publish_from_raspi(aws_iot_client, topic_1, msg, qos=Si91xAwsQos.QOS1)
                    time.sleep(1)
                    logger.info(
                        f"\n aws_iot_client publishing message{i + 1} on topic:'{topic_2}' \nQOS:'{Si91xAwsQos.QOS1}'"
                        f"\nMessage{i + 1} with length:'{len(msg)} bytes'\nMessage{i + 1} is:'{msg}'")
                    aws_obj.publish_from_raspi(aws_iot_client, topic_2, msg, qos=Si91xAwsQos.QOS1)
                    recv_msg = aws_obj.receive_aws_messages_from_dut(wifi_dut, wait_time=15)
                    if recv_msg:
                        rc += 1
                        received_messages.append(recv_msg)
                        logger.info(f"Received message{rc}: '{recv_msg}'")
                count = len(received_messages)
                if count < 100:
                    logger.warning(
                        f"******* Received '{count}' messages out of {len(messages)} published messages *******")
                else:
                    logger.info(
                        f"************ Successfully received all {len(messages)} published messages ************\n")
                logger.info(f"Iteration '{iter_count + 1}' completed")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
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
        "region": 1,
        "region_code": "europe"
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": '11n', "security": 'WPA3', "region": 'Europe', "channel": 12})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_2_subscribers_rx_c537894(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                               sl_collections, aws_iot_client, utf_constants):
    """
    Verify MQTT funcyionality with 2 subscribers with different lengths and do Tx and Rx
    """
    iterations = utf_constants.get('iter_count')
    topic_1 = "topic_1_c537894"
    topic_2 = "topic_2_c537894"
    test_name = "test_wifi_sdk_c537894"
    client_id = 'client_c537894'
    messages = []
    for i in range(10):
        messages.append(text_generator(size=100))
    logger.info(f"Messages are:{messages}")

    try:
        capture_filename = "test_wifi_sdk_c537894"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=wifi_access_point.interfaces.wifi.channel)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client, messages=messages)

        for iter_count in range(iterations):
            assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), ("Failed to connect aws "
                                                                                 "server from DUT")
            logger.info("Connecting to AWS server from DUT is successful")
            aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
            aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=Si91xAwsQos.QOS1)
            aws_obj.subscribe_from_dut(wifi_dut, topic_2, qos=Si91xAwsQos.QOS1)
            aws_obj.subscribe_from_raspi(aws_iot_client, topic_1, qos=Si91xAwsQos.QOS1)
            aws_obj.subscribe_from_raspi(aws_iot_client, topic_2, qos=Si91xAwsQos.QOS1)
            wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
            time.sleep(5)

            received_messages = []
            logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
            rc = 0
            for i, msg in enumerate(messages):
                logger.info(
                    f"\n aws_iot_client publishing message{i + 1} on topic:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS1}'"
                    f"\nMessage{i + 1} with length:'{len(msg)} bytes'\nMessage{i + 1} is:'{msg}'")
                aws_obj.publish_from_raspi(aws_iot_client, topic_1, msg, qos=Si91xAwsQos.QOS1)
                time.sleep(1)
                logger.info(
                    f"\n aws_iot_client publishing message{i + 1} on topic:'{topic_2}' \nQOS:'{Si91xAwsQos.QOS1}'"
                    f"\nMessage{i + 1} with length:'{len(msg)} bytes'\nMessage{i + 1} is:'{msg}'")
                aws_obj.publish_from_raspi(aws_iot_client, topic_2, msg, qos=Si91xAwsQos.QOS1)
                recv_msg = aws_obj.receive_aws_messages_from_dut(wifi_dut, wait_time=15)
                if recv_msg:
                    rc += 1
                    received_messages.append(recv_msg)
                    logger.info(f"Received message{rc}: '{recv_msg}'")
                count = len(received_messages)
            if count < 100:
                logger.warning(
                    f"******* Received '{count}' messages out of {len(messages)} published messages *******")
            else:
                logger.info(
                    f"************ Successfully received all {len(messages)} published messages ************\n")
            logger.info(f"Iteration '{iter_count + 1}' completed")

            logger.info("Initiating aws_iot_disconnect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
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
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_2_publisher_tx_c537895(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                             sl_collections, aws_iot_client, utf_constants):
    """
    Verify MQTT functionality with 2 subscribers with different lengths and do Tx and Rx
    """
    iterations = utf_constants.get('iter_count')
    topic_1 = "topic_1_c537895"
    topic_2 = "topic_2_c537895"
    test_name = "test_wifi_sdk_c537895"
    client_id = 'client_c537895'

    # Generate messages1 and messages2 lists
    messages1 = [text_generator(size=100) for _ in range(10)]
    messages2 = [text_generator(size=110) for _ in range(10)]

    messages3 = []
    for msg1, msg2 in zip(messages1, messages2):
        messages3.append(msg1)  # Add element from messages1
        messages3.append(msg2)  # Add element from messages2

    logger.info(f"\n\n Messages3 are:{messages3}\n\n")

    try:
        capture_filename = "test_wifi_sdk_c537895"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        assert (len(scan_results) >= 1), "Scan failed"
        logger.info(scan_results)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=0,
                                            power_save=False, skip_scan=False)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client)

        for iter_count in range(iterations):
            assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), ("Failed to connect aws "
                                                                                 "server from DUT")
            logger.info("Connecting to AWS server from DUT is successful")
            aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
            aws_obj.subscribe_from_raspi(aws_iot_client, topic_1, qos=Si91xAwsQos.QOS0)
            aws_obj.subscribe_from_raspi(aws_iot_client, topic_2, qos=Si91xAwsQos.QOS0)
            wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
            time.sleep(5)

            for count, (msg1, msg2) in enumerate(zip(messages1, messages2)):
                # Logging for message from messages1 on topic_1
                logger.info(
                    f"\n\n *** DUT is publishing message {count + 1} on topic 1:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS0}'"
                    f"\nMessage{count + 1} with length:'{len(msg1)} bytes'\nMessage{count + 1} is:'{msg1}'*** \n\n")
                # Publishing msg1 to topic_1
                aws_obj.publish_from_dut(wifi_dut, topic_1, msg1, qos=Si91xAwsQos.QOS0)
                time.sleep(2)

                # Logging for message from messages2 on topic_2
                logger.info(
                    f"\n\n *** DUT is publishing message {count + 1} on topic 2:'{topic_2}' \nQOS:'{Si91xAwsQos.QOS0}'"
                    f"\nMessage{count + 1} with length:'{len(msg2)} bytes'\nMessage{count + 1} is:'{msg2}'*** \n\n")
                # Publishing msg2 for topic_2
                aws_obj.publish_from_dut(wifi_dut, topic_2, msg2, qos=Si91xAwsQos.QOS0)
                time.sleep(2)

            aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic_1, Si91xAwsQos.QOS0, messages3,
                                                     topic_1=topic_1, topic_2=topic_2)

            logger.info("Initiating aws_iot_disconnect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
            time.sleep(10)
            logger.info(f"\n\n\n *** ITERATION {iter_count} COMPLETED *** \n\n\n")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "bt_features": Si91xBTFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["intermediate-root-ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_aws_ca1_cert_tx_c687529(wifi_sniffer, wifi_access_point, wifi_dut, logger, sl_collections,
                                          aws_iot_client):
    """
    Connect to AWS server with root CA1 certificate and check whether Tx functionality
    """

    test_name = "test_wifi_sdk_c661500"
    messages = []
    for i in range(22):
        messages.append(text_generator(size=100))

    try:
        capture_filename = "test_wifi_sdk_c661500"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        assert (len(scan_results) >= 1), "Scan failed"
        logger.info(scan_results)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=0,
                                            power_save=True, skip_scan=False)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case=687529,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client, messages=messages, sleep=10)

        logger.info(f"**** Publishing MQTT data for 5 minutes....")
        aws_obj.start()
        aws_obj.wait_for_exit()

        logger.info("Initiating aws_iot_disconnect from DUT")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
        time.sleep(20)
        logger.info("\n")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "bt_features": Si91xBTFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["intermediate-root-combined.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_aws_combined_cert_tx_c688527(wifi_sniffer, wifi_access_point, wifi_dut, logger, sl_collections,
                                               aws_iot_client):
    """
    Connect to AWS server with combination of root CA1+CA3 certificate and check whether Tx functionality
    """

    test_name = "test_wifi_sdk_c661500"
    messages = []
    for i in range(50):
        messages.append(text_generator(size=100))

    try:
        capture_filename = "test_wifi_sdk_c661500"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        assert (len(scan_results) >= 1), "Scan failed"
        logger.info(scan_results)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=0,
                                            power_save=True, skip_scan=False)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case=687529,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client, messages=messages, sleep=2)

        logger.info(f"**** Publishing MQTT data for 5 minutes....")
        aws_obj.start()
        aws_obj.wait_for_exit()

        logger.info("Initiating aws_iot_disconnect from DUT")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
        time.sleep(20)
        logger.info("\n")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "bt_features": Si91xBTFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["intermediate-root-ca-3.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_aws_ca3_cert_tx_c688520(wifi_sniffer, wifi_access_point, wifi_dut, logger, sl_collections,
                                          aws_iot_client):
    """
    Connect to AWS server with root CA3 certificate and check whether Tx functionality
    """

    test_name = "test_wifi_sdk_c661500"
    messages = []
    for i in range(35):
        messages.append(text_generator(size=100))

    try:
        capture_filename = "test_wifi_sdk_c661500"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        assert (len(scan_results) >= 1), "Scan failed"
        logger.info(scan_results)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=0,
                                            power_save=True, skip_scan=False)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case=687529,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client, messages=messages, sleep=5)

        logger.info(f"**** Publishing MQTT data for 5 minutes....")
        aws_obj.start()
        aws_obj.wait_for_exit()

        logger.info("Initiating aws_iot_disconnect from DUT")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
        time.sleep(20)
        logger.info("\n")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "bt_features": Si91xBTFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["intermediate-root-ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_ca1_cert_rx_c687530(wifi_sniffer, wifi_access_point, wifi_dut, logger, sl_collections,
                                          aws_iot_client):
    """
    Connect to AWS server with root CA1 certificate and check whether Rx functionality
    """

    topic = "topic_c661501"
    test_name = "test_wifi_sdk_c661501"
    client_id = 'client_c661501'

    try:
        capture_filename = "test_wifi_sdk_c661501"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        assert (len(scan_results) >= 1), "Scan failed"
        logger.info(scan_results)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=0,
                                            power_save=True, skip_scan=False)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client)

        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id, port=443), ("Failed to connect aws "
                                                                                       "server from DUT")
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
        wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
        time.sleep(5)

        sw = Stopwatch()
        while sw.elapsed_sec < 300:

            message = text_generator(size=100)
            logger.info(
                f"\naws_iot_client publishing message on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                f"\nMessage with length:'{len(message)} bytes'\nMessage is:'{message}'")
            aws_obj.publish_from_raspi(aws_iot_client, topic, message, qos=Si91xAwsQos.QOS1)
            recv_msg = aws_obj.receive_aws_messages_from_dut(wifi_dut)

            logger.info(f"******** Received message: \n'{recv_msg}'")

            assert recv_msg == message, "Failed to receive message"

            logger.info(f"**** Successfully received published message ****\n")

            time.sleep(10)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "bt_features": Si91xBTFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["intermediate-root-ca-3.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_ca3_cert_rx_c688521(wifi_sniffer, wifi_access_point, wifi_dut, logger, sl_collections,
                                          aws_iot_client):
    """
    Connect to AWS server with root CA3 certificate and check whether Rx functionality
    """

    topic = "topic_c661501"
    test_name = "test_wifi_sdk_c661501"
    client_id = 'client_c661501'

    try:
        capture_filename = "test_wifi_sdk_c661501"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        assert (len(scan_results) >= 1), "Scan failed"
        logger.info(scan_results)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=0,
                                            power_save=True, skip_scan=False)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client)

        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id, port=443), ("Failed to connect aws "
                                                                                       "server from DUT")
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
        wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
        time.sleep(5)

        sw = Stopwatch()
        while sw.elapsed_sec < 300:

            message = text_generator(size=100)
            logger.info(
                f"\naws_iot_client publishing message on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                f"\nMessage with length:'{len(message)} bytes'\nMessage is:'{message}'")
            aws_obj.publish_from_raspi(aws_iot_client, topic, message, qos=Si91xAwsQos.QOS1)
            recv_msg = aws_obj.receive_aws_messages_from_dut(wifi_dut)

            logger.info(f"******** Received message: \n'{recv_msg}'")

            assert recv_msg == message, "Failed to receive message"

            logger.info(f"**** Successfully received published message ****\n")

            time.sleep(10)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "bt_features": Si91xBTFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["intermediate-root-combined.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_combined_cert_rx_c688528(wifi_sniffer, wifi_access_point, wifi_dut, logger, sl_collections,
                                               aws_iot_client):
    """
    Connect to AWS server with combination of root CA1+CA3 certificate and check whether Rx functionality
    """

    topic = "topic_c661501"
    test_name = "test_wifi_sdk_c661501"
    client_id = 'client_c661501'

    try:
        capture_filename = "test_wifi_sdk_c661501"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        assert (len(scan_results) >= 1), "Scan failed"
        logger.info(scan_results)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=0,
                                            power_save=True, skip_scan=False)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client)

        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id, port=443), ("Failed to connect aws "
                                                                                       "server from DUT")
        logger.info("Connecting to AWS server from DUT is successful")
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS1)
        wifi_dut.interfaces.wifi.aws_iot_mqtt_autoreconnect_set_status()
        time.sleep(5)

        sw = Stopwatch()
        while sw.elapsed_sec < 300:

            message = text_generator(size=100)
            logger.info(
                f"\naws_iot_client publishing message on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS1}'"
                f"\nMessage with length:'{len(message)} bytes'\nMessage is:'{message}'")
            aws_obj.publish_from_raspi(aws_iot_client, topic, message, qos=Si91xAwsQos.QOS1)
            recv_msg = aws_obj.receive_aws_messages_from_dut(wifi_dut)

            logger.info(f"******** Received message: \n'{recv_msg}'")

            assert recv_msg == message, "Failed to receive message"

            logger.info(f"**** Successfully received published message ****\n")

            time.sleep(5)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "bt_features": Si91xBTFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["intermediate-root-ca-3.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "bt_features": Si91xBTFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["intermediate-root-ca-3.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.end_state("remote_wiseconnect3",
                       wifi=["wifi_powersave_disable", "disassociated", "aws_unsubscribe", "aws_disconnect"])
def test_wifi_sdk_aws_two_client_with_same_client_id_c537898(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                             sl_collections, aws_iot_client, remote_wiseconnect3):
    """
    Negative case : Verify when two clients having same client id
    """

    test_name = "test_wifi_sdk_c661500"
    messages = []
    for i in range(10):
        messages.append(text_generator(size=100))

    try:
        capture_filename = "test_wifi_sdk_c661500"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        assert (len(scan_results) >= 1), "Scan failed"
        logger.info(scan_results)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=0,
                                            power_save=True, skip_scan=False)

        scan_results = remote_wiseconnect3.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        assert (len(scan_results) >= 1), "Scan failed"
        logger.info(scan_results)

        remote_wiseconnect3.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=remote_wiseconnect3,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=0,
                                            power_save=True, skip_scan=False)

        aws_obj1 = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case=687529,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client, messages=messages, sleep=5)

        aws_obj2 = AwsConnection(wifi_dut=remote_wiseconnect3, wifi_access_point=wifi_access_point, test_case=687529,
                                 wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                 aws_iot_client=aws_iot_client, messages=messages, sleep=5)

        logger.info(f"**** Publishing MQTT data on two devices with same client ID....")
        try:
            aws_obj1.start()
            time.sleep(5)
            aws_obj2.start()

            aws_obj1.wait_for_exit()
            aws_obj2.wait_for_exit()

        except Exception as error:
            assert "SL_STATUS_AWS_CONNECTION_FAILURE" in str(error), "Connected with same client ID"
            logger.info(f"Exception occurred: {error} which is expected")

        logger.info("Initiating aws_iot_disconnect from DUT")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
        time.sleep(20)
        logger.info("\n")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W
                               | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "bt_features": Si91xBTFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["intermediate-root-ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_aws_ca1_cert_tx_with_internal_clk_c703343(wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                            sl_collections,aws_iot_client):
    """
    Connect to AWS server with root CA1 certificate and check whether Tx functionality using with Internal RC clk
    """

    test_name = "test_wifi_sdk_c661500"
    messages = []
    for i in range(22):
        messages.append(text_generator(size=100))

    try:
        capture_filename = "test_wifi_sdk_c661500"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        assert (len(scan_results) >= 1), "Scan failed"
        logger.info(scan_results)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            channel=0,
                                            power_save=True, skip_scan=False)

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case=687529,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client, messages=messages, sleep=10)

        logger.info(f"**** Publishing MQTT data for 5 minutes....")
        aws_obj.start()
        aws_obj.wait_for_exit()

        logger.info("Initiating aws_iot_disconnect from DUT")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
        time.sleep(20)
        logger.info("\n")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
