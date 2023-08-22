import filecmp
import os
import random
import string
import time
from datetime import datetime
from retry import retry
import pytest
from threading import Thread
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.devices.rs911x import RS9116AsyncEventType
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116PowerSaveModes,
    RS9116CustomFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveProcedureTypes,
    DeviceConstants,
    RS9116AwsQos
)

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Connect to the AWS MQTT server
        5. Send or receive data on MQTT and verify packet loss tests 
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
    Reported by cg team : rashmi & team , vinod 
"""


def logger():
    return get_logger(__name__)


def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


class aws_connection:
    """
    Class to connect, subscribe, publish data from DUT/Raspi to AWS server.
    """

    @retry(Exception, delay=20, tries=5)
    def connect_to_aws_server_from_dut(self, wifi_dut):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @return: Boolean Value(True/False)
        """
        status = False
        try:
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False, thread=True)
            status = True
        except Exception as err:
            logger().error(str(err))
            if "0x2" in str(err):
                logger().warning("AWS server is not reachable from DUT, Please check your internet connection")
                wifi_dut.interfaces.wifi.aws_iot_disconnect(thread=True)
            time.sleep(10)
        assert status, "Connecting to AWS server from DUT is failed"
        return status

    @retry(Exception, delay=20, tries=5)
    def subscribe_from_dut(self, wifi_dut, topic, qos=RS9116AwsQos.QOS0):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param topic: Topic name to subscribe from DUT on AWS Server
        @param qos: QOS value to subscribe on aws topic(0/1)
        """
        logger().info(f"DUT is Subscribing on topic '{topic}' and QOS:'{RS9116AwsQos.QOS0}'")
        wifi_dut.interfaces.wifi.aws_iot_subscribe(topic, qos=qos, timeout=10, thread=True)

    @retry(Exception, delay=20, tries=5)
    def publish_from_dut(self, wifi_dut, topic, message, qos, timeout=20):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param topic: Topic name to subscribe from DUT on AWS Server.
        @param message: Data to publish from DUT on subscribed topic.
        @param qos: QOS value to publish data on aws topic(0/1).
        @param timeout: Timeout value to wait until command to be executed successfully.
        """
        wifi_dut.interfaces.wifi.aws_iot_publish(topic, message, qos=qos, timeout=timeout, thread=True)

    @retry(Exception, delay=20, tries=5)
    def connect_to_aws_server_from_raspi(self, aws_iot_client):
        """
        @param aws_iot_client: Fixture parameter to issue command in Raspi.
        """
        aws_iot_client.interfaces.aws_iot.aws_iot_connect()

    @retry(Exception, delay=20, tries=5)
    def subscribe_from_raspi(self, aws_iot_client, topic, qos=RS9116AwsQos.QOS0):
        """
        @param aws_iot_client: Fixture parameter to issue command in Raspi.
        @param topic: Topic name to subscribe from Raspi on AWS Server.
        @param qos: QOS value to subscribe on aws topic(0/1).
        """
        aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(topic, qos=qos)

    @retry(Exception, delay=20, tries=5)
    def publish_from_raspi(self, aws_iot_client, topic, messages, qos=RS9116AwsQos.QOS0):
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
    def validate_aws_messages(wifi_dut, topic, qos, messages):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param topic: Topic name which is subscribed on AWS Server.
        @param qos: QOS value which is subscribed on AWS Server(0/1).
        @param messages: Data which is published on aws topic.
        """
        logger().info("\nValidating received aws message")
        time.sleep(10)
        events = wifi_dut.interfaces.wifi.get_async_events(thread=True)
        count = 0
        iot_event = 0
        for event in events:
            if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
                iot_event = 1
                aws_event_qos = event.event_data.qos
                aws_event_topic = event.event_data.topic
                aws_event_payload = event.event_data.payload
                logger().info(
                    f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
                assert topic == aws_event_topic, f"received wrong topic, expected is {topic}"
                assert qos == aws_event_qos, "Received wrong QOS. expected is QOS0"
                if isinstance(messages, list):
                    assert messages[count] == aws_event_payload, "sent and received messages are not matching"
                else:
                    assert messages == aws_event_payload, "sent and received messages are not matching"
                count += 1
        assert iot_event == 1, f"published message '{messages[count]}' not received on DUT"
        logger().info("aws messages validated successfully")

    def connect_disconnect_aws(self, wifi_dut, messages, topic):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param topic: Topic name which is subscribed on AWS Server.
        @param messages: Data which is published on aws topic.
        """
        try:
            connect_count = 0
            logger().info("Initiating aws connect from DUT")
            assert self.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
            logger().info("Connecting to AWS server is successful")
            connect_count += 1
            time.sleep(2)

            subscribe_count = 0
            for count in range(1, 11):
                try:
                    logger().info(f"DUT is Subscribing on topic '{topic}' and QOS:'{RS9116AwsQos.QOS1}'")
                    wifi_dut.interfaces.wifi.aws_iot_subscribe(topic, qos=RS9116AwsQos.QOS1, timeout=10, thread=True)
                    time.sleep(3)
                    subscribe_count += 1
                    break
                except Exception as err:
                    logger().info(f"Subscribing on topic '{topic}' failed. retry count->{count}")
                    if count == 10:
                        raise err
                    time.sleep(10)
            assert subscribe_count, "Subscribing to topic from DUT is failed"

            count = 0
            for msg in messages:
                count += 1
                logger().info(f"\nDUT publishing message{count} on topic:'{topic}' \nQOS:'{RS9116AwsQos.QOS1}'"
                              f"\nMessage{count} with length:'{len(msg)} bytes'\nMessage{count} is:'{msg}'")
                self.publish_from_dut(wifi_dut, topic, msg, qos=RS9116AwsQos.QOS1)
                time.sleep(5)

            logger().info("\nValidating received aws message")
            time.sleep(10)
            events = wifi_dut.interfaces.wifi.get_async_events(thread=True)
            count = 0
            iot_event = 0
            for event in events:
                if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
                    iot_event = 1
                    aws_event_qos = event.event_data.qos
                    aws_event_topic = event.event_data.topic
                    aws_event_payload = event.event_data.payload
                    logger().info(
                        f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
                    assert topic == aws_event_topic, f"received wrong topic, expected is {topic}"
                    assert RS9116AwsQos.QOS1 == aws_event_qos, "Received wrong QOS. expected is QOS0"
                    assert messages[count] == aws_event_payload, "sent and received messages are not matching"
                    count += 1
            assert iot_event == 1, f"published message '{messages[count]}' not received on DUT"
            logger().info("Received aws message validated successfully")

            logger().info("DUT Unsubscribing from aws topic")
            wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic, timeout=30, thread=True)
            return connect_count, subscribe_count
        finally:
            logger().info("Initiating aws_iot_disconnect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_disconnect(thread=True)
            time.sleep(20)
            logger().info("\n")


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
            aws_connection().publish_from_dut(self.wifi_dut, self.topic, msg, qos=self.qos, timeout=10)
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


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.RsaKeyWith4096Support | RS9116ExtCustomFeatureBitMap.SslCertWith4096Support | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "ca_cert": ["start_field.pem"],
            "client_cert": ["client-certificate.crt"],
            "client_key": ["private-key.key"],
        }
    ),
    pytest.mark.start_state("wifi_access_point", wifi="ap_enabled"),
    pytest.mark.firmware_app("test_aws")
]


@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("iterations", [1])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_connect_sub_publish_c19548(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                                 iterations, sl_collections):
    """
    Connect to AWS MQTT server subscribe to topic and publish message on the same topic. Initiate disconnection and
    check the connection stability.
    """
    topic_1 = "sdk/test/Python"
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
            result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=30,
                                                                     retry_count=3, rejoin_parms=[0, 4, 40, 0])
            dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger.info(f'AP BSSID = {ap_bssid}')
            logger.info(f"Device mac address: {dut_mac_address}")

            aws_obj = aws_connection()
            logger.info("Initiating aws connect from DUT")
            assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
            logger.info("Connecting to AWS server from DUT is successful")
            time.sleep(2)
            aws_obj.subscribe_from_dut(wifi_dut, topic_1)
            count = 0
            for msg in messages:
                count += 1
                logger.info(f"\nDUT publishing message{count} on topic:'{topic_1}' \nQOS:'{RS9116AwsQos.QOS0}'"
                            f"\nMessage{count} with length:'{len(msg)} bytes'\nMessage{count} is:'{msg}'")
                aws_obj.publish_from_dut(wifi_dut, topic_1, msg, qos=RS9116AwsQos.QOS0)
                time.sleep(2)
            aws_obj.validate_aws_messages(wifi_dut, topic_1, RS9116AwsQos.QOS0, messages)

            logger.info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
            logger.info(f"Iteration '{iter_count + 1}' completed")
    except Exception as error:
        raise error


@pytest.mark.config('wifi_access_point', wifi={"channel": 6})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_connect_after_wifi_reconnection_c4053(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut,
                                                            logger, sl_collections):
    """
    Connect to AWS MQTT server after connecting to AP second time, the first time connection is closed intentionally by
    DUT by executing disconnect command
    """
    topic_1 = "sdk/test/Python"
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
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point, thread=True)
        time.sleep(10)
        logger.info("Initiating wifi leave for first time")
        wifi_dut.interfaces.wifi.leave(thread=True)

        logger.info("Joining to AP for second time")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=30,
                                                                 retry_count=3, rejoin_parms=[0, 4, 40, 0])

        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = aws_connection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        time.sleep(2)
        aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=RS9116AwsQos.QOS1)

        count = 0
        for msg in messages:
            count += 1
            logger.info(f"\nDUT publishing message{count} on topic:'{topic_1}' \nQOS:'{RS9116AwsQos.QOS1}'"
                        f"\nMessage{count} with length:'{len(msg)} bytes'\nMessage{count} is:'{msg}'")
            aws_obj.publish_from_dut(wifi_dut, topic_1, msg, qos=RS9116AwsQos.QOS1)
            time.sleep(2)
        aws_obj.validate_aws_messages(wifi_dut, topic_1, RS9116AwsQos.QOS1, messages)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_server_not_respond_c4062(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut, logger,
                                               sl_collections):
    """
    DUT functionality when server doesn't respond to tcp connection request sent by DUT when DUT is trying to connect
    AWS MQTT server.
    """
    topic_1 = "sdk/test/Python"
    try:
        messages = []
        for i in range(10):
            messages.append(text_generator(size=10))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_C4062"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=30,
                                                                 rejoin_parms=[0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = aws_connection()
        error_code = None
        for count in range(5):
            try:
                with pytest.raises(WlanError) as exc_info:
                    wifi_dut.interfaces.wifi.aws_iot_connect(hostname="www.google.com", load_cert=False, thread=True)
                error_code = exc_info.value.error_code
                assert exc_info.value.error_code == 0x0021, "DUT sent wrong error code, expected is 0x0021"
                logger.info(
                    f"DUT sent error code '{exc_info.value.error_code}' when server is not responding which is expected")
                break
            except Exception as error:
                logger.info(str(error))
        assert error_code == 0x0021, "DUT sent wrong error code, expected is 0x0021"

        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        time.sleep(2)
        aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=RS9116AwsQos.QOS0)

        count = 0
        for msg in messages:
            count += 1
            logger.info(f"\nDUT publishing message{count} on topic:'{topic_1}' \nQOS:'{RS9116AwsQos.QOS0}'"
                        f"\nMessage{count} with length:'{len(msg)} bytes'\nMessage{count} is:'{msg}'")
            aws_obj.publish_from_dut(wifi_dut, topic_1, msg, qos=RS9116AwsQos.QOS0)
            time.sleep(2)
        aws_obj.validate_aws_messages(wifi_dut, topic_1, RS9116AwsQos.QOS0, messages)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
@pytest.mark.parametrize("test_run_time", [1800])
def test_wifi_sdk_aws_connect_disconnect_sequence_c19552(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut,
                                                         logger, sl_collections, test_run_time):
    """
    Connect to AWS MQTT server subscribe to topic publish the data on the topic unsubscribe the subscribed topic and
    disconnect to server. Repeat the above steps continuously in loop for 30 minutes
    """
    topic_1 = "sdk/test/Python"
    expected_error_count = 5
    try:
        messages = []
        for i in range(5):
            messages.append(text_generator(size=20))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_C19552"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=30,
                                                                 rejoin_parms=[0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        sw = Stopwatch()
        error_count = 0
        connect_count = 0
        subscribe_count = 0
        logger.info(f"Running the aws connect and disconnect test for '{test_run_time}' seconds")
        aws_obj = aws_connection()
        while sw.elapsed_sec <= test_run_time:
            time_left = int((test_run_time - sw.elapsed_sec) / 60)
            logger.info(f"Remaining time to complete test is '{time_left}' minutes")
            try:
                con_count, sub_count = aws_obj.connect_disconnect_aws(wifi_dut, messages, topic_1)
                connect_count += con_count
                subscribe_count += sub_count
            except Exception as err:
                error_count += 1
                logger.error(str(err))

        assert connect_count, "Failed to connect to aws_server from DUT"
        assert subscribe_count, "Failed to subscribe to aws_server from DUT"
        logger.info(f"Number of times aws_connect_disconnect failure in span of 30 minutes:'{error_count}'")
        assert error_count <= expected_error_count, f"aws connect_publish_disconnect_sequence failed more than '{expected_error_count}' times in 30 minutes of test run"

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.config('wifi_access_point', wifi={"channel": 6})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_publish_data_with_different_length_c19553(firmware_loader, wifi_sniffer, wifi_access_point,
                                                                wifi_dut, logger, sl_collections):
    """
    Publish data over subscribed topic with different lengths(1 byte, 10 bytes, 100 bytes, 512 bytes, 1000 bytes, 1390 bytes)
    """
    topic_1 = "sdk/test/Python"
    try:
        message1 = text_generator(size=1)
        message2 = text_generator(size=10)
        message3 = text_generator(size=100)
        message4 = text_generator(size=512)
        message5 = text_generator(size=1000)
        # message6 = text_generator(size=1390)

        message = {"message1": message1, "message2": message2, "message3": message3, "message4": message4,
                   "message5": message5}
        logger.info(f"Messages are:{message}")

        capture_filename = "test_aws_publish_data_with_different_length_TC19553"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=30,
                                                                 rejoin_parms=[0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = aws_connection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        time.sleep(2)
        aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=RS9116AwsQos.QOS0)

        for message_key, message_value in message.items():
            logger.info(f"\nDUT publishing message on topic:'{topic_1}' \nQOS:'{RS9116AwsQos.QOS0}'"
                        f"\nMessage with length:'{len(message_value)} bytes'\nMessage is:'{message_value}'")
            aws_obj.publish_from_dut(wifi_dut, topic_1, message_value, qos=RS9116AwsQos.QOS0, timeout=10)
            aws_obj.validate_aws_messages(wifi_dut, topic_1, RS9116AwsQos.QOS0, message_value)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_receive_data_over_subscribed_topic_with_different_lengths_c19554(firmware_loader, wifi_sniffer,
                                                                                       wifi_access_point, wifi_dut,
                                                                                       aws_iot_client, logger,
                                                                                       sl_collections):
    """
    Receive data over subscribed topic with different lengths(1,100 bytes,500 bytes, 1000 bytes,1390 bytes)
    """
    topic_1 = "sdk/test/Python"
    try:
        message1 = text_generator(size=10)
        message2 = text_generator(size=100)
        # message3 = text_generator(size=500)
        # message4 = text_generator(size=1000)
        # message5 = text_generator(size=1390)

        message = {"message1": message1, "message2": message2}
        logger.info(f"Messages are:{message}")

        capture_filename = "test_aws_receive_data_over_subscribed_topic_with_different_lengths_C19554"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=30,
                                                                 rejoin_parms=[0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        aws_obj = aws_connection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        time.sleep(2)

        aws_obj.connect_to_aws_server_from_raspi()
        aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=RS9116AwsQos.QOS1)

        for message_key, message_value in message.items():
            logger.info(f"\naws_iot_client publishing message on topic:'{topic_1}' \nQOS:'{RS9116AwsQos.QOS1}'"
                        f"\nMessage with length:'{len(message_value)} bytes'\nMessage is:'{message_value}'")
            aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic_1, message_value, qos=RS9116AwsQos.QOS1)
            aws_obj.validate_aws_messages(wifi_dut, topic_1, RS9116AwsQos.QOS1, message_value)

        logger.info("Initiating aws_iot disconnect from aws_iot_client")
        aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_connection_when_client_id_is_null_c19558(firmware_loader, wifi_sniffer, wifi_access_point,
                                                               wifi_dut, logger, sl_collections):
    """
    Verify AWS connection when "AWS_IOT_MQTT_CLIENT_ID" is NULL and clean session flag set to true
    """
    try:
        capture_filename = "test_aws_connection_when_client_id_is_null_C19558"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=30,
                                                                 rejoin_parms=[0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        logger.info("Initiating aws connect with client_id 'null' and clean_session flag '1'")
        status = False
        for count in range(5):
            try:
                wifi_dut.interfaces.wifi.aws_iot_connect(client_id="NULL", clean_session=1, load_cert=False,
                                                         thread=True)
                status = True
                break
            except Exception as err:
                logger.error(str(err))
                logger.info(f"Connecting to aws server from DUT is failed...retry_count{count + 1}\n")
                if "0x2" in str(err):
                    wifi_dut.interfaces.wifi.aws_iot_disconnect(thread=True)
                time.sleep(10)
        assert status, "Connecting to AWS server from DUT is failed"

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")
        time.sleep(5)

        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.config('wifi_access_point', wifi={"channel": 6})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_tcp_shutdown_c19546(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut, aws_iot_client,
                                          logger, sl_collections):
    """
    Connect to AWS MQTT server subscribe to any topic, Receive data on the subscribed topic. Close the TCP connection
    and check the Connection stability.
    """
    topic_1 = "sdk/test/Python"
    try:
        message1 = text_generator(size=100)
        message = {"message1": message1}
        logger.info(f"Messages are:{message}")

        capture_filename = "test_aws_tcp_shutdown_C19546"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=30,
                                                                 rejoin_parms=[0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        aws_obj = aws_connection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        time.sleep(2)

        aws_obj.connect_to_aws_server_from_raspi()
        aws_obj.subscribe_from_dut(wifi_dut, topic_1, qos=RS9116AwsQos.QOS0)

        for message_key, message_value in message.items():
            logger.info(f"\naws_iot_client publishing message on topic:'{topic_1}' \nQOS:'{RS9116AwsQos.QOS0}'"
                        f"\nMessage with length:'{len(message_value)} bytes'\nMessage is:'{message_value}'")
            aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic_1, message_value, qos=RS9116AwsQos.QOS0)
            aws_obj.validate_aws_messages(wifi_dut, topic_1, RS9116AwsQos.QOS0, message_value)

        logger.info("Initiating AWS shutdown")
        wifi_dut.interfaces.wifi.close_sockets()
        logger.info("AWS shutdown success")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.config('wifi_access_point', wifi={"channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_wifi_sdk_aws_publish_message_in_thread1_and_receive_message_in_thread2_c19566(firmware_loader, wifi_sniffer,
                                                                                       wifi_access_point,
                                                                                       wifi_dut, aws_iot_client,
                                                                                       logger, sl_collections):
    """
    Connect to AWS MQTT server Subscribe to the topic. Publish a message in one thread on the topic and receive a
    message in the second thread on the same topic
    """
    topic_1 = "sdk/test/Python"
    try:
        messages = []
        for i in range(10):
            messages.append(text_generator(size=10))
        logger.info(f"Messages are:{messages}")

        capture_filename = "test_wifi_sdk_C19566"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=30,
                                                                 rejoin_parms=[0, 4, 40, 0])
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        aws_obj = aws_connection()
        logger.info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut), "Failed to connect aws server from DUT"
        logger.info("Connecting to AWS server from DUT is successful")
        time.sleep(2)

        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
        aws_obj.subscribe_from_raspi(aws_iot_client, topic_1, qos=RS9116AwsQos.QOS1)

        t1 = aws_publish_message_Thread(wifi_dut, topic_1, messages, qos=RS9116AwsQos.QOS1)
        t2 = aws_receive_message_Thread(aws_iot_client, topic_1, messages, qos=RS9116AwsQos.QOS1)

        logger.info("aws_publish_message_thread + aws_receive_message_thread execution starts....")
        t1.start()
        t2.start()

        t1.wait_for_exit(True)
        t2.wait_for_exit(True)

        logger.info("Unsubscribing from aws topic from aws_iot_client")
        aws_iot_client.interfaces.aws_iot.aws_iot_unsubscribe(topic_1)
        time.sleep(2)

        logger.info("Initiating aws_iot_disconnect from aws_iot_client")
        aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()
        time.sleep(2)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        logger.info(f"Device mac address: {dut_mac_address}")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        raise error

