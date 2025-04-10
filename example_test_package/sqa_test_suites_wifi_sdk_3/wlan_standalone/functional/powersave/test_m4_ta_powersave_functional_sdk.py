import time
import pytest
import string
from retry import retry
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
import re
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xJoinFeatureBitMap, Si91xAwsQos, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.logger import get_logger
import random
from random import randint
from utf.utils.stopwatch import Stopwatch
from AWSIoTPythonSDK.core.protocol.internal.clients import ClientStatus
from utf.utils.iperf.iperf_utils import ping


def logger():
    return get_logger(__name__)

def text_generator(size=2000):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


""" Test Steps:
        1. Configure the DUT in Wlan & coex mode for 2.4Ghz.
        2. Initiate the Scan from DUT.
        3. Initiate the connection with third party Access Point.
        4. Run the traffic TCP/UDP TX & RX.
        5. Verify m4 and ta wake up when received the wireless packet.  

    setup requirement:
        1. DUT(SiWG917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. NUC

    Author: RaviNemali 
"""


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
                                       timeout=120, isWillMsgPresent=False, expected_status=SLStatus.SL_STATUS_OK,
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

pytestmark = [pytest.mark.firmware_app("test_480K_M4SS_320K")]


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
def test_m4_interrupt_ta_listen_interval_C514372(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                                 remote_socket, protocol, utf_constants, sl_collections):
    """Execute M4 Wakes up from sleep randomly,M4 will interrupt TA to wakeup(TA-Listen interval Based powersave),
    TA will send TCP Tx to TCP Server"""
    listen_interval = 1100
    try:
        logger().info("starting the sniffer")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_m4_interrupt_ta_listen_interval_C514372')
        time.sleep(2)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                         Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(5, 1)
        dut_add_dict = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                           wifi_access_point=wifi_access_point,
                                                           associated=wifi_dut.interfaces.wifi.associated,
                                                           retry_count=3, ping_after_power_save=False,
                                                           ping_count=10, power_save=False,
                                                           mode='power_save',
                                                           listen_interval=1100
                                                           )

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        wifi_dut.interfaces.wifi.enable_bt_power_save(2, 0)

        logger().info("Starting TCP server socket remotely")
        local_port = randint(6000, 6100)
        remote_socket.interfaces.socket.interface = "eth1"
        logger().info("Starting TCP Server socket at remote device")
        remote_socket.interfaces.socket.start_server(port=local_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = remote_socket.interfaces.socket.server_port

        logger().info(f"DUT opens tcp client socket")
        tcp_socket_id = wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        bind_response = wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id, device_ip=dut_add_dict['device_ip'],
                                                      server_port=server_port,
                                                      timeout=5)
        logger().info(f"Bind socket successfully: {bind_response}")

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=server_ip,
                                                          server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")

        for packets in range(5):
            logger().info("DUT Sending Data packets")
            bytes_sent = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data="tapowersaveinterrupt",
                                                                timeout=30)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
            logger().info("Setting TCP socket receive timeout in remote server")
            remote_socket.interfaces.socket.set_recv_timeout(socket_type=0)
            recv_data = remote_socket.interfaces.socket.recv_data_tcp(data_size=len("tapowersaveinterrupt"))
            logger().info(f"data received : {recv_data}")
            packets = packets + 1
            logger().info(f"total packets received at the remote socket: {packets}")
            wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=10000)

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=tcp_socket_id)
        remote_socket.interfaces.socket.stop()

    except Exception as e:
        logger().error(f"Exception occurred: {e}")
        raise e


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
def test_m4_interrupt_ta_DTIM_based_C514376(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                            remote_socket, protocol, utf_constants, sl_collections):
    """Execute M4 Wakes up from sleep randomly,M4 will interrupt TA to wakeup(TA-DTIM Based powersave),
    TA will send TCP Tx to TCP Server"""
    try:
        logger().info("starting the sniffer")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_m4_interrupt_ta_DTIM_based_C514376')
        time.sleep(2)

        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(5, 1)
        dut_add_dict = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                           wifi_access_point=wifi_access_point,
                                                           associated=wifi_dut.interfaces.wifi.associated,
                                                           retry_count=3, ping_after_power_save=False,
                                                           ping_count=10, power_save=False,
                                                           mode='power_save'
                                                           )

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        wifi_dut.interfaces.wifi.enable_bt_power_save(2, 0)

        logger().info("Starting TCP server socket remotely")
        local_port = randint(6000, 6100)
        remote_socket.interfaces.socket.interface = "eth1"
        logger().info("Starting TCP Server socket at remote device")
        remote_socket.interfaces.socket.start_server(port=local_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = remote_socket.interfaces.socket.server_port

        logger().info(f"DUT opens tcp client socket")
        tcp_socket_id = wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        bind_response = wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id, device_ip=dut_add_dict['device_ip'],
                                                      server_port=server_port,
                                                      timeout=5)
        logger().info(f"Bind socket success: {bind_response}")

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=server_ip,
                                                          server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")

        for packets in range(5):
            logger().info("DUT Sending Data packets")
            bytes_sent = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data="tapowersaveinterrupt",
                                                                timeout=30)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
            logger().info("Setting TCP socket receive timeout in remote server")
            remote_socket.interfaces.socket.set_recv_timeout(socket_type=0)
            recv_data = remote_socket.interfaces.socket.recv_data_tcp(data_size=len("tapowersaveinterrupt"))
            logger().info(f"data received : {recv_data}")
            packets = packets + 1
            logger().info(f"total packets received at the remote socket: {packets}")
            wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=10000)

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=tcp_socket_id)
        remote_socket.interfaces.socket.stop()

    except Exception as e:
        logger().error(f"Exception occurred: {e}")
        raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "ca_cert": ["intermediate-root-ca-3.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate-aws-mqtt.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["starfield-ca.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_tcp_rx_ta_interrupt_m4_wakeup_c514371(wifi_sniffer, wifi_access_point, wifi_dut, logger, sl_collections,
                                               aws_iot_client):
    """
    Execute TCP Rx received from TCP client to TA ,
    TA will wake up from sleep(TA- Listen interval Based powersave),TA will interrupt M4 to wakeup
    """
    topic = "topic_c661501"
    test_name = "test_tcp_rx_ta_interrupt_m4_wakeup_c514371"
    client_id = 'client_c661501'
    try:
        capture_filename = "test_tcp_rx_ta_interrupt_m4_wakeup_c514371"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                         Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        time.sleep(5)
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(5, 1)

        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                           wifi_access_point=wifi_access_point,
                                                           associated=wifi_dut.interfaces.wifi.associated,
                                                           retry_count=3, ping_after_power_save=False,
                                                           ping_count=10, power_save=False,
                                                           mode='power_save'
                                                           )

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client)


        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id, port=443), ("Failed to connect aws "
                                                                                       "server from DUT")

        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        wifi_dut.interfaces.wifi.enable_bt_power_save(2, 0)

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
        wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=10000)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "ca_cert": ["intermediate-root-ca-3.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate-aws-mqtt.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["starfield-ca.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA3', "region": 'Korea', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "disassociated"])
def test_tcp_rx_ta_interrupt_m4_wakeup_DTIM_based_power_save_c514375(wifi_sniffer, wifi_access_point, wifi_dut, logger, sl_collections,
                                               aws_iot_client):
    """
    Execute TCP Rx received from TCP client to TA ,TA will wake up from sleep(TA-DTIM Based powersave),
    TA will interrupt M4 to wakeup
    """
    topic = "topic_c661501"
    test_name = "test_tcp_rx_ta_interrupt_m4_wakeup_DTIM_based_power_save_c514375"
    client_id = 'client_c661501'
    try:
        capture_filename = "test_tcp_rx_ta_interrupt_m4_wakeup_DTIM_based_power_save_c514375"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(5, 1)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                           wifi_access_point=wifi_access_point,
                                                           associated=wifi_dut.interfaces.wifi.associated,
                                                           retry_count=3, ping_after_power_save=False,
                                                           ping_count=10, power_save=False,
                                                           mode='power_save'
                                                           )

        aws_obj = AwsConnection(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, test_name=test_name,
                                aws_iot_client=aws_iot_client)

        assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id, port=443), ("Failed to connect aws "
                                                                                       "server from DUT")
        logger.info("Connecting to AWS server from DUT is successful")

        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        wifi_dut.interfaces.wifi.enable_bt_power_save(2, 0)

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

        wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=10000)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
def test_wifi_sdk_deinit_functionality_after_m4_wakeup_c708580(wifi_dut, wifi_access_point, sl_collections):
    """Verify sl_wifi_deinit functionality after M4 awakes from sleep when WLAN is in connected state"""
    try:
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake()
        wifi_dut.interfaces.wifi.get_fw_version()
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       power_save=False,
                                                       wifi_access_point=wifi_access_point,
                                                       associated=wifi_dut.interfaces.wifi.associated,
                                                       channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(f"Device IP address : {dut_addr['device_ip']}")
        logger().info(f"Device MAC address : {dut_addr['dut_mac_address']}")
        wifi_dut.interfaces.wifi.set_filter_broadcast()
        mode = 'power_save_low_latency'
        logger().info(f"....Applying performance profile mode : {mode}")
        wifi_dut.interfaces.wifi.set_performance_profile(mode, 0, 0, 0, 0)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=2000)
        wifi_dut.interfaces.wifi.deinit()

    except Exception as error:
        logger().error(f"Exception occurred: {error}")
        raise error
