import filecmp
import os
import random
import re
import string
import time
from datetime import datetime
import requests
from retry import retry
import pytest
from threading import Thread
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils import get_tls_certificate_dir
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
    Si91xCertIdentifier
)
from AWSIoTPythonSDK.core.protocol.internal.clients import ClientStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers

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


def text_generator(size=200):
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
            aws_connection().publish_from_dut(self.wifi_dut, self.topic, msg, qos=self.qos)
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


class aws_connection:
    """
    Class to connect, subscribe, publish data from DUT/Raspi to AWS server.
    """

    def __init__(self):
        self.aws_inited = False

    @retry(Exception, delay=15, tries=3)
    def connect_to_aws_server_from_dut(self, wifi_dut, client_id, iscleansession=True, timeout=120):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param client_id: mqtt client id for aws connection.
        @param iscleansession: Boolean Value(True/False).
        @param timeout: Timeout value to wait until command to be executed successfully.
        @return: Boolean Value(True/False).
        """
        status = False
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        try:
            if not self.aws_inited:
                wifi_dut.interfaces.wifi.aws_iot_mqtt_init(client_id=client_id, iscleansession=iscleansession,
                                                           timeout=timeout)
                time.sleep(2)
                self.aws_inited = True
            wifi_dut.interfaces.wifi.aws_iot_mqtt_connect(timeout=timeout)
            status = True
        except Exception as error:
            logger().warning(f"AWS server is not reachable from DUT\nException:{error}")

        assert status, "Connecting to AWS server from DUT is failed"
        return status

    @retry(Exception, delay=15, tries=5)
    def subscribe_from_dut(self, wifi_dut, topic, qos=Si91xAwsQos.QOS0, timeout=120):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param topic: Topic name to subscribe from DUT on AWS Server
        @param qos: QOS value to subscribe on aws topic(0/1)
        @param timeout: Timeout value to wait until command to be executed successfully.
        """
        logger().info(f"DUT is Subscribing on topic '{topic}' and QOS:'{Si91xAwsQos.QOS0}'")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_subscribe(topic_name=topic, qos=qos, timeout=timeout)

    @retry(Exception, delay=15, tries=5)
    def publish_from_dut(self, wifi_dut, topic, message, qos, timeout=120):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param topic: Topic name to subscribe from DUT on AWS Server.
        @param message: Data to publish from DUT on subscribed topic.
        @param qos: QOS value to publish data on aws topic(0/1).
        @param timeout: Timeout value to wait until command to be executed successfully.
        """
        wifi_dut.interfaces.wifi.aws_iot_mqtt_publish(topic_name=topic, qos=qos, payload=message, timeout=timeout)

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
        aws_iot_client.interfaces.aws_iot.received_messages.clear()
        aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(topic, qos=qos)
        status = aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, f"Subscribe on topic:'{topic}' is failed from aws_iot_client"

    @retry(Exception, delay=15, tries=3)
    def publish_from_raspi(self, aws_iot_client, topic, messages, qos=Si91xAwsQos.QOS0):
        """
        @param aws_iot_client: Fixture parameter to issue command in Raspi.
        @param topic: Topic name to subscribe from Raspi on AWS Server.
        @param messages: Data to publish from Raspi on subscribed topic.
        @param qos: QOS value to subscribe on aws topic(0/1).
        """
        i = 0
        for msg in messages:
            i += 1
            logger().info(f"\naws_iot_client publishing message{i} on topic:'{topic}' \nQOS:'{qos}'"
                          f"\nMessage{i} with length:'{len(msg)} bytes'\nMessage{i} is:'{msg}'")
            aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic, msg, qos=qos)
            time.sleep(5)

    @staticmethod
    def validate_aws_messages_from_raspi(aws_iot_client, topic, qos, messages, wait_time=10):
        """
        @param aws_iot_client: Fixture parameter to issue command in Raspi.
        @param topic: Topic name which is subscribed on AWS Server.
        @param qos: QOS value which is subscribed on AWS Server(0/1).
        @param messages: Data which is published on aws topic.
        @param wait_time: Wait time value until data received from aws server.
        """
        logger().info("\nValidating received aws message")
        time.sleep(wait_time)
        recv_messages = aws_iot_client.interfaces.aws_iot.get_received_messages()
        for count, msg in enumerate(messages):
            logger().info(f"Received message{count + 1} is: '{recv_messages[count].payload.decode()}'")
            logger().info(f"Received message{count + 1} topic is: '{recv_messages[count].topic}'")
            logger().info(f"Received message{count + 1} qos is: '{recv_messages[count].qos}'")
            assert recv_messages[count].payload.decode() == messages[count], "Received wrong message in aws_iot_client"
            assert recv_messages[count].topic == topic, "Received wrong topic in aws_iot_client"
            assert recv_messages[count].qos == qos, "Received wrong qos in aws_iot_client"
        logger().info("aws messages validated successfully")


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
                1),
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
            "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
            "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
            "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        }
    ),
    pytest.mark.start_state("wifi_access_point", wifi="ap_enabled"),
    pytest.mark.firmware_app("test_aws")
]


@pytest.mark.config('wifi_access_point', wifi={"channel": 3})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_connect_sub_publish_c19548(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut, logger,
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

            aws_obj = aws_connection()
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


@pytest.mark.config('wifi_access_point', wifi={"channel": 8})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_connect_after_wifi_reconnection_c4053(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut,
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

        aws_obj = aws_connection()
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


@pytest.mark.config('wifi_access_point', wifi={"channel": 8})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_publish_message_in_thread1_and_receive_message_in_thread2_c19566(firmware_loader, wifi_sniffer,
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

        aws_obj = aws_connection()
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


@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_tx_after_rejoin_qos0_C19555(firmware_loader, switch, wifi_sniffer, wifi_access_point, wifi_dut,
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

        aws_obj = aws_connection()
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


@pytest.mark.config('wifi_access_point', wifi={"channel": 6})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_tx_after_rejoin_qos1_c19556(firmware_loader, switch, wifi_sniffer, wifi_access_point, wifi_dut,
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

        aws_obj = aws_connection()
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


""" Below testcases needs rework and will be uncommented for next upcoming announcements """
# @pytest.mark.config('wifi_access_point', wifi={"channel": 11})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_server_not_respond_c4062(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut, logger,
#                                                sl_collections):
#     """
#     DUT functionality when server doesn't respond to tcp connection request sent by DUT when DUT is trying to connect
#     AWS MQTT server.
#     """
#     topic_1 = "sdk/test/Python"
#     try:
#         messages = []
#         for i in range(10):
#             messages.append(text_generator(size=10))
#         logger.info(f"Messages are:{messages}")
#
#         capture_filename = "test_wifi_sdk_C4062"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         aws_obj = aws_connection()
#         error_code = None
#         for count in range(5):
#             try:
#                 with pytest.raises(WlanError) as exc_info:
#                     wifi_dut.interfaces.wifi.aws_iot_connect(hostname="www.google.com", load_cert=False)
#                 error_code = exc_info.value.error_code
#                 assert exc_info.value.error_code == 0x0021, "DUT sent wrong error code, expected is 0x0021"
#                 logger.info(
#                     f"DUT sent error code '{exc_info.value.error_code}' when server is not responding which is expected")
#                 break
#             except Exception as error:
#                 logger.info(str(error))
#         assert error_code == 0x0021, "DUT sent wrong error code, expected is 0x0021"
#
#         logger.info("Initiating aws connect from DUT")
#         assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
#         logger.info("Connecting to AWS server from DUT is successful")
#         time.sleep(2)
#         aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=Si91xAwsQos.QOS0)
#
#         count = 0
#         for msg in messages:
#             count += 1
#             logger.info(f"\nDUT publishing message{count} on topic:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS0}'"
#                         f"\nMessage{count} with length:'{len(msg)} bytes'\nMessage{count} is:'{msg}'")
#             aws_obj.publish_from_dut(wifi_dut, topic_1, msg, qos=Si91xAwsQos.QOS0)
#             time.sleep(2)
#         aws_obj.validate_aws_messages(wifi_dut, topic_1, Si91xAwsQos.QOS0, messages)
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 1})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# @pytest.mark.parametrize("test_run_time", [1800])
# def test_wifi_sdk_aws_connect_disconnect_sequence_c19552(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut,
#                                                          logger, sl_collections, test_run_time):
#     """
#     Connect to AWS MQTT server subscribe to topic publish the data on the topic unsubscribe the subscribed topic and
#     disconnect to server. Repeat the above steps continuously in loop for 30 minutes
#     """
#     topic_1 = "sdk/test/Python"
#     expected_error_count = 5
#     try:
#         messages = []
#         for i in range(5):
#             messages.append(text_generator(size=20))
#         logger.info(f"Messages are:{messages}")
#
#         capture_filename = "test_wifi_sdk_C19552"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         sw = Stopwatch()
#         error_count = 0
#         connect_count = 0
#         subscribe_count = 0
#         logger.info(f"Running the aws connect and disconnect test for '{test_run_time}' seconds")
#         aws_obj = aws_connection()
#         while sw.elapsed_sec <= test_run_time:
#             time_left = int((test_run_time - sw.elapsed_sec) / 60)
#             logger.info(f"Remaining time to complete test is '{time_left}' minutes")
#             try:
#                 con_count, sub_count = aws_obj.connect_disconnect_aws(wifi_dut, messages, topic_1)
#                 connect_count += con_count
#                 subscribe_count += sub_count
#             except Exception as err:
#                 error_count += 1
#                 logger.error(str(err))
#
#         assert connect_count, "Failed to connect to aws_server from DUT"
#         assert subscribe_count, "Failed to subscribe to aws_server from DUT"
#         logger.info(f"Number of times aws_connect_disconnect failure in span of 30 minutes:'{error_count}'")
#         assert error_count <= expected_error_count, f"aws connect_publish_disconnect_sequence failed more than '{expected_error_count}' times in 30 minutes of test run"
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 6})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_publish_data_with_different_length_c19553(firmware_loader, wifi_sniffer, wifi_access_point,
#                                                                 wifi_dut, logger, sl_collections):
#     """
#     Publish data over subscribed topic with different lengths(1 byte, 10 bytes, 100 bytes, 512 bytes, 1000 bytes, 1390 bytes)
#     """
#     topic_1 = "sdk/test/Python"
#     try:
#         message1 = text_generator(size=1)
#         message2 = text_generator(size=10)
#         message3 = text_generator(size=100)
#         message4 = text_generator(size=512)
#         message5 = text_generator(size=1000)
#         # message6 = text_generator(size=1390)
#
#         message = {"message1": message1, "message2": message2, "message3": message3, "message4": message4,
#                    "message5": message5}
#         logger.info(f"Messages are:{message}")
#
#         capture_filename = "test_aws_publish_data_with_different_length_TC19553"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         aws_obj = aws_connection()
#         logger.info("Initiating aws connect from DUT")
#         assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
#         logger.info("Connecting to AWS server from DUT is successful")
#         time.sleep(2)
#         aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=Si91xAwsQos.QOS0)
#
#         for message_key, message_value in message.items():
#             logger.info(f"\nDUT publishing message on topic:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS0}'"
#                         f"\nMessage with length:'{len(message_value)} bytes'\nMessage is:'{message_value}'")
#             aws_obj.publish_from_dut(wifi_dut, topic_1, message_value, qos=Si91xAwsQos.QOS0, timeout=10)
#             aws_obj.validate_aws_messages(wifi_dut, topic_1, Si91xAwsQos.QOS0, message_value)
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 11})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_receive_data_over_subscribed_topic_with_different_lengths_c19554(firmware_loader, wifi_sniffer,
#                                                                                        wifi_access_point, wifi_dut,
#                                                                                        aws_iot_client, logger,
#                                                                                        sl_collections):
#     """
#     Receive data over subscribed topic with different lengths(1,100 bytes,500 bytes, 1000 bytes,1390 bytes)
#     """
#     topic_1 = "sdk/test/Python"
#     try:
#         message1 = text_generator(size=10)
#         message2 = text_generator(size=100)
#         # message3 = text_generator(size=500)
#         # message4 = text_generator(size=1000)
#         # message5 = text_generator(size=1390)
#
#         message = {"message1": message1, "message2": message2}
#         logger.info(f"Messages are:{message}")
#
#         capture_filename = "test_aws_receive_data_over_subscribed_topic_with_different_lengths_C19554"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         aws_obj = aws_connection()
#         logger.info("Initiating aws connect from DUT")
#         assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
#         logger.info("Connecting to AWS server from DUT is successful")
#         time.sleep(2)
#
#         aws_obj.connect_to_aws_server_from_raspi()
#         aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=Si91xAwsQos.QOS1)
#
#         for message_key, message_value in message.items():
#             logger.info(f"\naws_iot_client publishing message on topic:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS1}'"
#                         f"\nMessage with length:'{len(message_value)} bytes'\nMessage is:'{message_value}'")
#             aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic_1, message_value, qos=Si91xAwsQos.QOS1)
#             aws_obj.validate_aws_messages(wifi_dut, topic_1, Si91xAwsQos.QOS1, message_value)
#
#         logger.info("Initiating aws_iot disconnect from aws_iot_client")
#         aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()
#
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 1})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_connection_when_client_id_is_null_c19558(firmware_loader, wifi_sniffer, wifi_access_point,
#                                                                wifi_dut, logger, sl_collections):
#     """
#     Verify AWS connection when "AWS_IOT_MQTT_CLIENT_ID" is NULL and clean session flag set to true
#     """
#     try:
#         capture_filename = "test_aws_connection_when_client_id_is_null_C19558"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         logger.info("Initiating aws connect with client_id 'null' and clean_session flag '1'")
#         status = False
#         for count in range(5):
#             try:
#                 wifi_dut.interfaces.wifi.aws_iot_connect(client_id="NULL", clean_session=1, load_cert=False,
#                                                          )
#                 status = True
#                 break
#             except Exception as err:
#                 logger.error(str(err))
#                 logger.info(f"Connecting to aws server from DUT is failed...retry_count{count + 1}\n")
#                 if "0x2" in str(err):
#                     wifi_dut.interfaces.wifi.aws_iot_disconnect()
#                 time.sleep(10)
#         assert status, "Connecting to AWS server from DUT is failed"
#
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#         time.sleep(5)
#
#         logger.info("Stop sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 6})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_tcp_shutdown_c19546(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut, aws_iot_client,
#                                           logger, sl_collections):
#     """
#     Connect to AWS MQTT server subscribe to any topic, Receive data on the subscribed topic. Close the TCP connection
#     and check the Connection stability.
#     """
#     topic_1 = "sdk/test/Python"
#     try:
#         message1 = text_generator(size=100)
#         message = {"message1": message1}
#         logger.info(f"Messages are:{message}")
#
#         capture_filename = "test_aws_tcp_shutdown_C19546"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         aws_obj = aws_connection()
#         logger.info("Initiating aws connect from DUT")
#         assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
#         logger.info("Connecting to AWS server from DUT is successful")
#         time.sleep(2)
#
#         aws_obj.connect_to_aws_server_from_raspi()
#         aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=Si91xAwsQos.QOS0)
#
#         for message_key, message_value in message.items():
#             logger.info(f"\naws_iot_client publishing message on topic:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS0}'"
#                         f"\nMessage with length:'{len(message_value)} bytes'\nMessage is:'{message_value}'")
#             aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic_1, message_value, qos=Si91xAwsQos.QOS0)
#             aws_obj.validate_aws_messages(wifi_dut, topic_1, Si91xAwsQos.QOS0, message_value)
#
#         logger.info("Initiating AWS shutdown")
#         wifi_dut.interfaces.wifi.close_sockets()
#         logger.info("AWS shutdown success")
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 1})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.parametrize("test_run_time", [1800])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_publish_a_message_on_the_topic_for_every_10_minutes_c19567(firmware_loader, wifi_dut,
#                                                                                  wifi_access_point, sl_collections,
#                                                                                  wifi_sniffer, logger, test_run_time):
#     """
#     Connect to AWS MQTT server. Subscribe to the topic. Move DUT to sleep. Wake up every 10 minutes and publish a
#     message on the topic. Then go to sleep. Repeat the same test for 24 hours.
#     """
#     topic_1 = "sdk/test/Python"
#     try:
#         messages = []
#         for i in range(5):
#             messages.append(text_generator(size=20))
#         logger.info(f"Messages are:{messages}")
#
#         capture_filename = "test_wifi_sdk_C19567"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         aws_obj = aws_connection()
#         logger.info("Initiating aws connect from DUT")
#         assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
#         logger.info("Connecting to AWS server from DUT is successful")
#         time.sleep(2)
#         aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=Si91xAwsQos.QOS0)
#
#         sw = Stopwatch()
#         count = 0
#         while sw.elapsed_sec < test_run_time:
#             try:
#                 for msg in messages:
#                     count += 1
#                     logger.info(f"\nDUT publishing message{count} on topic:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS0}'"
#                                 f"\nMessage{count} with length:'{len(msg)} bytes'\nMessage{count} is:'{msg}'")
#                     aws_obj.publish_from_dut(wifi_dut, topic_1, msg, qos=Si91xAwsQos.QOS0, timeout=10)
#                     time.sleep(2)
#                 aws_obj.validate_aws_messages(wifi_dut, topic_1, Si91xAwsQos.QOS0, messages)
#             except Exception as err:
#                 logger.info(str(err))
#
#             logger.info("DUT is going to sleep for 10 minutes")
#             time.sleep(600)
#
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 6})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.parametrize("iterations", [1])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_receive_functionality_while_receiving_100_mqtt_messages_continuously_c19561(firmware_loader,
#                                                                                                   wifi_sniffer,
#                                                                                                   wifi_dut, logger,
#                                                                                                   aws_iot_client,
#                                                                                                   wifi_access_point,
#                                                                                                   sl_collections,
#                                                                                                   iterations):
#     """
#     MQTT receive functionality while receiving 100 MQTT messages continuously each with MQTT data length 300 bytes
#     """
#     topic_1 = "mytesttopic/1"
#     try:
#         # 100 messages of 300 bytes of random data
#         messages = []
#         for i in range(100):
#             messages.append(text_generator(size=300))
#         logger.info(f"Messages are:{messages}")
#
#         capture_filename = "test_wifi_sdk_C19561"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         aws_obj = aws_connection()
#         logger.info("Initiating aws connect from DUT")
#         assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
#         logger.info("Connecting to AWS server from DUT is successful")
#         time.sleep(2)
#
#         aws_obj.connect_to_aws_server_from_raspi()
#         aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=Si91xAwsQos.QOS1)
#
#         for iter_count in range(iterations):
#             logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
#             i = 0
#             iot_event = 0
#             count = 0
#             for msg in messages:
#                 for retry_count in range(20):
#                     event_received = False
#                     try:
#                         i += 1
#                         logger.info(
#                             f"\naws_iot_client publishing message{i} on topic:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS1}'"
#                             f"\nMessage{i} with length:'{len(msg)} bytes'\nMessage{i} is:'{msg}'")
#                         aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic_1, msg, qos=Si91xAwsQos.QOS1)
#                         time.sleep(10)
#                         events = wifi_dut.interfaces.wifi.get_async_events()
#                         logger.info("\nValidating received aws message")
#                         for event in events:
#                             if event.event_type == AsyncEventIdentifiers.AWSIoTMQTTMessage:
#                                 iot_event += 1
#                                 aws_event_qos = event.event_data.qos
#                                 aws_event_topic = event.event_data.topic
#                                 aws_event_payload = event.event_data.payload
#                                 logger.info(
#                                     f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
#                                 assert topic_1 == aws_event_topic, "message is not received on subscribed topic"
#                                 assert Si91xAwsQos.QOS1 == aws_event_qos, "Received wrong QOS. expected is QOS0"
#                                 assert messages[
#                                            count] == aws_event_payload, "sent and received messages are not matching"
#                                 count += 1
#                                 event_received = True
#                             if event.event_type == AsyncEventIdentifiers.TCP_REMOTE_TERMINATE:
#                                 logger.info("tcp socket got terminated...Waiting for reconnection from DUT")
#                                 time.sleep(200)
#                                 sl_collections.ping(dut_ip, 30, 5)
#                     except:
#                         logger.info(f"Published message not received in DUT--->retry_count:{retry_count}")
#                     if event_received:
#                         break
#             assert iot_event == 100, f"published message '{messages[count]}' not received on DUT"
#             logger.info("aws messages validated successfully")
#             logger.info(f"Iteration '{iter_count + 1}' completed")
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 11})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.parametrize("total_bytes", [20])
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={"thread_config": {"wifi": {"count": 2, "stack_len": 2048}, }})
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_receive_100_mqtt_messages_over_2_subscribed_topics_c19563(firmware_loader, wifi_sniffer,
#                                                                                 wifi_access_point,
#                                                                                 wifi_dut, sl_collections,
#                                                                                 aws_iot_client, logger, total_bytes):
#     """
#     MQTT receive functionality over SSL while receiving 100 MQTT messages continuously each with MQTT data length 2048
#     bytes over two subscribed topics, one with granted QOS 0 and another with granted QOS1 when RSA key size used is 2048 bit length
#     """
#     try:
#         topic_1 = "mytesttopic/1"
#         topic_2 = "mytesttopic/2"
#         messages = []
#         for i in range(100):
#             messages.append(text_generator(size=total_bytes))
#         logger.info(f"Messages are:{messages}")
#
#         capture_filename = "test_wifi_sdk_C19563"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         aws_obj = aws_connection()
#         logger.info("Initiating aws connect from DUT")
#         assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
#         logger.info("Connecting to AWS server from DUT is successful")
#         time.sleep(2)
#         aws_obj.connect_to_aws_server_from_raspi()
#         aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=Si91xAwsQos.QOS0)
#         aws_obj.subscribe_from_dut(wifi_dut, topic_2, qos=Si91xAwsQos.QOS1)
#
#         qos0_thread = Thread(target=aws_obj.publish_from_raspi,
#                              args=(aws_iot_client, topic_1, messages, Si91xAwsQos.QOS0))
#         qos1_thread = Thread(target=aws_obj.publish_from_raspi,
#                              args=(aws_iot_client, topic_1, messages, Si91xAwsQos.QOS1))
#
#         qos0_thread.start()
#         time.sleep(10)
#         qos1_thread.start()
#
#         qos0_thread.join()
#         qos1_thread.join()
#
#         time.sleep(10)
#         events = wifi_dut.interfaces.wifi.get_async_events()
#         logger.info("\nValidating received aws messages")
#         iot_event = 0
#         qos0_count = 0
#         qos1_count = 0
#         for event in events:
#             if event.event_type == AsyncEventIdentifiers.AWSIoTMQTTMessage:
#                 aws_event_qos = event.event_data.qos
#                 aws_event_topic = event.event_data.topic
#                 aws_event_payload = event.event_data.payload
#                 if aws_event_qos == Si91xAwsQos.QOS0:
#                     logger.info(
#                         f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
#                     assert topic_1 == aws_event_topic, f"Received wrong topic. expected is topic1:{topic_1}"
#                     assert aws_event_qos == Si91xAwsQos.QOS0, "Received wrong QOS. expected is QOS0"
#                     assert messages[qos0_count] == aws_event_payload, "sent and received messages are not matching"
#                     qos0_count += 1
#                 else:
#                     logger.info(
#                         f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
#                     assert topic_2 == aws_event_topic, f"Received wrong topic. expected is topic2:{topic_2}"
#                     assert aws_event_qos == Si91xAwsQos.QOS1, "Received wrong QOS. expected is QOS0"
#                     assert messages[qos1_count] == aws_event_payload, "sent and received messages are not matching"
#                     qos1_count += 1
#                 iot_event += 1
#         assert iot_event == 200, f"Some of the published message not received on DUT"
#         logger.info("aws messages validated successfully")
#
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 1})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.parametrize("iterations", [1])
# @pytest.mark.parametrize("publish_len, total_bytes", [(490, 1024000)])  # 493 is max limit
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_data_integrity_check_after_receiving_1mb_of_data_over_mqtt_c19562(firmware_loader, wifi_dut,
#                                                                                         wifi_sniffer,
#                                                                                         aws_iot_client,
#                                                                                         wifi_access_point, logger,
#                                                                                         publish_len, sl_collections,
#                                                                                         total_bytes, iterations):
#     """
#     Data integrity check After receiving 1Mb file over MQTT over SSL when RSA key size used is 2048 bit length
#     """
#     topic_1 = "mytesttopic/1"
#     try:
#         current_time = time.time()
#         capture_filename = "test_wifi_sdk_C19562"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         aws_obj = aws_connection()
#         logger.info("Initiating aws connect from DUT")
#         assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
#         logger.info("Connecting to AWS server from DUT is successful")
#         time.sleep(2)
#
#         aws_obj.connect_to_aws_server_from_raspi()
#         aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=Si91xAwsQos.QOS0)
#
#         data = text_generator(size=total_bytes)
#         file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
#         tx_file = "./reports/" + capture_filename + "_tx_file_" + file_time_stamp + ".txt"
#         with open(tx_file, "w") as temp:
#             temp.write(data)
#
#         msgs = []
#         recv_count = 0
#         for iter_count in range(iterations):
#             logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
#             with open(tx_file, "r") as temp:
#                 while 1:
#                     recv_fail = 0
#                     data = temp.read(publish_len)
#                     if data == '':
#                         break
#                     else:
#                         for retry_count in range(10):
#                             try:
#                                 logger.info(
#                                     f"\naws_iot_client publishing message on topic:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS0}'"
#                                     f"\nData with length:'{len(data)} bytes'\nData is:'{data}'")
#                                 aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic_1, data, qos=Si91xAwsQos.QOS0)
#                                 time.sleep(3)
#                                 events = wifi_dut.interfaces.wifi.get_async_events()
#                                 logger.info("Fetching received aws messages")
#                                 recv_count = 0
#                                 for event in events:
#                                     if event.event_type == AsyncEventIdentifiers.AWSIoTMQTTMessage:
#                                         aws_event_qos = event.event_data.qos
#                                         aws_event_topic = event.event_data.topic
#                                         aws_event_payload = event.event_data.payload
#                                         assert topic_1 == aws_event_topic, "received topic is not matching with subscribed topic"
#                                         assert Si91xAwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
#                                         assert data == aws_event_payload, "sent and received messages are not matching"
#                                         recv_fail = 0
#                                         recv_count = 1
#                                     if event.event_type == AsyncEventIdentifiers.TCP_REMOTE_TERMINATE:
#                                         logger.info("tcp socket got terminated...Waiting for reconnection from DUT")
#                                         time.sleep(200)
#                                 assert recv_count == 1, "Published message not received on DUT"
#                                 msgs.append(aws_event_payload)
#                             except:
#                                 recv_fail = 1
#                                 time.sleep(20)
#                                 logger.info(f"Published message not received on DUT-->retry_count:{retry_count + 1}")
#                             if recv_count:
#                                 break
#                         if recv_fail:
#                             logger.info("Published message not received on DUT and test case will fail")
#                             break
#
#             logger.info("Validating 1mb of data by comparing tx_file and rx_file")
#             file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
#             rx_file = "./reports/" + capture_filename + f"_rx_file_{iter_count}" + file_time_stamp + ".txt"
#             if len(msgs):
#                 with open(rx_file, "w") as recv:
#                     for data in msgs:
#                         recv.write(data)
#             if not os.path.exists(rx_file):
#                 logger.info("No aws data received at receiver")
#             result = filecmp.cmp(tx_file, rx_file, shallow=False)
#             assert result, "Data loss observed, Contents of tx file and rx file not matched"
#             logger.info("Contents of tx_file and rx_file are same")
#             logger.info(f"Iteration '{iter_count + 1}' completed")
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 6})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.parametrize("iterations", [1])
# @pytest.mark.parametrize("publish_len, total_bytes", [(90, 102400)])  # 100 is max limit 1024000-filesize
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_data_integrity_check_after_sending_1mb_of_data_over_mqtt_c19564(firmware_loader, wifi_sniffer,
#                                                                                       wifi_access_point, wifi_dut,
#                                                                                       aws_iot_client, logger,
#                                                                                       publish_len, sl_collections,
#                                                                                       total_bytes, iterations):
#     """
#     Data integrity check after sending 1Mb of data over MQTT over SSL when RSA key size used is 2048 bits
#     """
#     topic_1 = "mytesttopic/1"
#     try:
#         current_time = time.time()
#         capture_filename = "test_wifi_sdk_C19564"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         aws_obj = aws_connection()
#         logger.info("Initiating aws connect from DUT")
#         assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
#         logger.info("Connecting to AWS server from DUT is successful")
#         time.sleep(2)
#
#         aws_obj.connect_to_aws_server_from_raspi()
#         aws_obj.subscribe_from_raspi(aws_iot_client, topic_1, qos=Si91xAwsQos.QOS1)
#
#         data = text_generator(size=total_bytes)
#         file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
#         tx_file = "./reports/" + capture_filename + "_tx_file_" + file_time_stamp + ".txt"
#         with open(tx_file, "w") as temp:
#             temp.write(data)
#
#         recv_messages = []
#         for iter_count in range(iterations):
#             logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
#             with open(tx_file, "r") as temp:
#                 while 1:
#                     data = temp.read(publish_len)
#                     if data == '':
#                         break
#                     else:
#                         for count in range(30):
#                             try:
#                                 logger.info(
#                                     f"\nDUT publishing data on topic:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS1}'"
#                                     f"\nData with length:'{len(data)} bytes'\nData is:'{data}'")
#                                 aws_obj.publish_from_dut(wifi_dut, topic_1, data, qos=Si91xAwsQos.QOS1, timeout=10)
#                                 time.sleep(5)
#                                 logger.info("Fetching received aws message")
#                                 messages = aws_iot_client.interfaces.aws_iot.get_received_messages()
#                                 logger.info(f"Data received is: {messages[0].payload.decode()}")
#                                 recv_messages.append(messages[0])
#                                 assert data == messages[
#                                     0].payload.decode(), "Published message not received in aws_iot_client"
#                                 aws_iot_client.interfaces.aws_iot.received_messages = []
#                                 break
#                             except:
#                                 events = wifi_dut.interfaces.wifi.get_async_events()
#                                 for event in events:
#                                     if event.event_type == AsyncEventIdentifiers.TCP_REMOTE_TERMINATE or count >= 15:
#                                         logger.info("tcp socket got terminated...Waiting for reconnection from DUT")
#                                         time.sleep(200)
#                                 logger.info(f"Publishing message is failed. retry count->{count + 1}")
#                                 time.sleep(20)
#             msgs = []
#             for msg in recv_messages:
#                 msgs.append(msg.payload.decode())
#                 assert msg.topic == topic_1, "Received wrong topic in aws_iot_client"
#                 assert msg.qos == Si91xAwsQos.QOS1, "Received wrong qos in aws_iot_client"
#
#             logger.info("Validating 1mb of data by comparing tx_file an rx_file")
#             file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
#             rx_file = "./reports/" + capture_filename + f"_rx_file_{iter_count}" + file_time_stamp + ".txt"
#             if len(msgs):
#                 with open(rx_file, "w") as recv:
#                     for data in msgs:
#                         recv.write(data)
#             if not os.path.exists(rx_file):
#                 logger.info("No aws data received at receiver")
#             result = filecmp.cmp(tx_file, rx_file, shallow=False)
#             assert result, "Data loss observed, Contents of tx file and rx file not matched"
#             logger.info("Contents of tx_file and rx_file are same")
#             logger.info(f"Iteration '{iter_count + 1}' completed")
#
#         logger.info("Unsubscribing from aws topic from aws_iot_client")
#         aws_iot_client.interfaces.aws_iot.aws_iot_unsubscribe(topic_1)
#         time.sleep(2)
#
#         logger.info("Initiating aws_iot disconnect from aws_iot_client")
#         aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 11})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.parametrize("iterations", [2])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_check_rejoin_failure_functionality_of_dut_c19549(firmware_loader, switch, wifi_sniffer,
#                                                                        wifi_access_point, sl_collections,
#                                                                        wifi_dut, logger, iterations):
#     topic_1 = "sdk/test/Python"
#     try:
#         messages = []
#         for i in range(5):
#             messages.append(text_generator(size=10))
#         logger.info(f"Messages are:{messages}")
#
#         capture_filename = "test_wifi_sdk_C19549"
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
#         time.sleep(5)
#
#         ap_bssid = None
#         dut_mac_address = None
#         for iteration in range(iterations):
#             logger.info(f"Initiating test for iteration:'{iteration + 1}'")
#             wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=10, scan_interval=6,
#                                                                      beacon_missed_count=40, first_time_retry_enable=0,
#                                                                      )
#             logger.info(f"Initiating wlan join from DUT")
#             for join_count in range(3):
#                 try:
#                     wifi_dut.interfaces.wifi.associated = False
#                     wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel,
#                                                   )
#                     time.sleep(3)
#                     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#                     time.sleep(5)
#                     break
#                 except Exception as e:
#                     logger.info(f"Error found:{str(e)} ----> Count{join_count} ")
#                     if "0x2" in str(e):
#                         logger.info(
#                             f"Error found:{str(e)} ----> Device already in connected step need to disconnect before connect")
#                         logger.info("Initiating disconnect for cleanup")
#                         wifi_dut.interfaces.wifi.leave(skip_check_for_association=True)
#                         wifi_dut.interfaces.wifi.associated = False
#                     if join_count == 2:
#                         raise e
#                     time.sleep(5)
#
#             dut_ip = None
#             for ip_count in range(4):
#                 try:
#                     ip_config = wifi_dut.interfaces.wifi.start_ip()
#                     assert isinstance(ip_config,
#                                       wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
#                     dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
#                     break
#                 except:
#                     logger.info(f"Get IP address through dhcp process is failed. retry count -> {ip_count + 1}")
#                     time.sleep(10)
#             assert dut_ip, "ip setting in DUT has failed"
#             logger.info(f'DUT ip {dut_ip}')
#
#             logger.info("Initiating wlan power save on DUT")
#             wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
#             if ap_bssid is None:
#                 ap_bssid = wifi_access_point.interfaces.wifi.bssid
#                 logger.info(f'AP BSSID = {ap_bssid}')
#             if dut_mac_address is None:
#                 dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
#                 logger.info(f"Device mac address: {dut_mac_address}")
#
#             logger.info(f"Initiating ping to DUT ip {dut_ip} after power save")
#             assert sl_collections.ping(dut_ip, 30, 5), "Unable to ping to DUT"
#
#             aws_obj = aws_connection()
#             logger.info("Initiating aws connect from DUT")
#             assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
#             logger.info("Connecting to AWS server from DUT is successful")
#             time.sleep(2)
#             aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=Si91xAwsQos.QOS1)
#
#             send_count = 0
#             while 1:
#                 msg = messages[send_count]
#                 logger.info(f"\nDUT publishing message{send_count + 1} on topic:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS1}'"
#                             f"\nMessage{send_count + 1} with length:'{len(msg)} bytes'\nMessage{send_count + 1} is:'{msg}'")
#                 aws_obj.publish_from_dut(wifi_dut, topic_1, msg, qos=Si91xAwsQos.QOS1, timeout=10)
#                 send_count += 1
#                 time.sleep(5)
#                 if send_count == int(len(messages)):
#                     break
#             aws_obj.validate_aws_messages(wifi_dut, topic_1, Si91xAwsQos.QOS1, messages)
#
#             try:
#                 logger.info("DUT Unsubscribing from aws topic")
#                 wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=30)
#                 time.sleep(3)
#                 logger.info("Initiating aws_iot disconnect from DUT")
#                 wifi_dut.interfaces.wifi.aws_iot_disconnect()
#                 time.sleep(3)
#             except:
#                 logger.info("DUT already in disconnected from aws server")
#
#             logger.info("\n\nTurning off the AP")
#             switch.interfaces.pdu_switch.turn_off(delay=20)
#             logger.info("Successfully powered off AP")
#
#             logger.info("Checking for rejoin fail event from dut, this may take some time....")
#             sw = Stopwatch()
#             rejoin_msg = 0
#             while sw.elapsed_sec <= 300:
#                 events = wifi_dut.interfaces.wifi.get_async_events()
#                 if len(events):
#                     for event in events:
#                         if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT:
#                             rejoin_msg = 1
#                 if rejoin_msg:
#                     break
#             assert rejoin_msg == 1, f"Rejoin Error not found from DUT even after AP is switched off for 300 seconds for iteration:'{iteration + 1}'"
#             logger.info("Rejoin Error Received from DUT")
#
#             logger.info("\n\nAgain turning on the AP")
#             switch.interfaces.pdu_switch.turn_on(delay=60)
#             logger.info("Successfully powered on AP")
#             logger.info(f"Iteration '{iteration + 1}' completed")
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         time.sleep(10)
#         sl_collections.oin_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config('wifi_access_point', wifi={"channel": 11})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "#aws_unsubscribe", "aws_disconnect",
#                              "disassociated"])
# def test_wifi_sdk_aws_rx_over_subscribed_topic_after_rejoin_qos1_c19559(firmware_loader, switch, wifi_sniffer,
#                                                                         wifi_access_point, wifi_dut, aws_iot_client,
#                                                                         logger, sl_collections):
#     topic_1 = "sdk/test/Python"
#     try:
#         messages = []
#         for i in range(10):
#             messages.append(text_generator(size=100))
#         logger.info(f"Messages are:{messages}")
#
#         capture_filename = "test_wifi_sdk_C19559"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, ping_count=30, retry_count=3,
#                                                      rejoin_parms=[0, 4, 40, 0])
#         dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         aws_obj = aws_connection()
#         logger.info("Initiating aws connect from DUT")
#         assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
#         logger.info("Connecting to AWS server from DUT is successful")
#         time.sleep(2)
#
#         aws_obj.connect_to_aws_server_from_raspi()
#         aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=Si91xAwsQos.QOS1)
#
#         send_count = 0
#         ap_power_off = 0
#         while 1:
#             if ap_power_off:
#                 logger.info("Turning off the AP")
#                 switch.interfaces.pdu_switch.turn_off(delay=20)
#                 logger.info("Successfully powered off AP")
#                 logger.info("Again turning on the AP")
#                 switch.interfaces.pdu_switch.turn_on(delay=100)
#                 ap_power_off = 0
#                 logger.info("Successfully powered on AP")
#                 logger.info("Pinging to DUT to check rejoin process is completed or not")
#                 status = sl_collections.ping(dut_ip, 30, 5)
#                 assert status, "Pinging to DUT is failed, DUT not rejoined to AP"
#
#             msg = messages[send_count]
#             logger.info(f"\naws_iot_client publishing message on topic:'{topic_1}' \nQOS:'{Si91xAwsQos.QOS1}'"
#                         f"\nMessage with length:'{len(msg)} bytes'\nMessage is:'{msg}'")
#             aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic_1, msg, qos=Si91xAwsQos.QOS1)
#             time.sleep(5)
#             send_count = send_count + 1
#             if send_count == int(len(messages) / 4):
#                 ap_power_off = 1
#             if send_count == int(len(messages)):
#                 break
#         aws_obj.validate_aws_messages(wifi_dut, topic_1, Si91xAwsQos.QOS0, messages)
#
#         logger.info("Initiating aws_iot disconnect from aws_iot_client")
#         aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         sl_collections.oin_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
