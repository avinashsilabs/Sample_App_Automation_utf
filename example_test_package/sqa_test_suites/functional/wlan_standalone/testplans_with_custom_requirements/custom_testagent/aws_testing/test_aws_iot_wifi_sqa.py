import filecmp
import os
import random
import string
import time
from datetime import datetime
from threading import Thread
import pytest
from utf.utils.iperf.iperf_utils import ping
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


def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger):
    ping_count = 10
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    scan_fail = 1
    for count in range(1, 3):
        try:
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")

    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap"
    )

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=20,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
    join_fail = 1
    for count in range(1, 3):
        try:
            logger.info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            join_fail = 0
            break
        except:
            logger.info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
            time.sleep(1)
    if join_fail:
        logger.info(f"Joining to the AP has failed")
        assert join_fail == 0, "Joining to the AP is failed"

    ip_fail = 1
    for count in range(1, 3):
        try:
            # DUT gets ipaddress through DHCP process after start_ip API is executed
            logger.info("DUT gets ipaddress through DHCP ")
            wifi_dut.interfaces.wifi.start_ip(timeout=60)
            ip_fail = 0
            break
        except:
            logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    if ip_fail:
        logger.info(f"DUT unable to get IP address")
        assert ip_fail == 0, "ip setting in DUT has failed"

    logger.info("Initiating wlan power save on DUT")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger.info("Initiating bt power save on DUT")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    assert ping(device_ip, ping_count), "Unable to ping to DUT"


def ApWirelessOff(wifi_access_point, wait_time, logger):
    time.sleep(1)
    logger.info(f"Disabling Wireless in AP")
    wifi_access_point.interfaces.wifi.stop_ap()
    logger.info(f"Disabled Wireless in AP")
    time.sleep(wait_time)
    logger.info(f"Enabling Wireless in AP")
    wifi_access_point.interfaces.wifi.start_ap()


def logger():
    return get_logger(__name__)


class aws_publish_message_Thread(ThreadBase):
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
            logger().info(f"DUT is publishing message{send_count + 1}:'{msg}' on topic:{self.topic}")
            self.wifi_dut.interfaces.wifi.aws_iot_publish(self.topic, msg, qos=RS9116AwsQos.QOS1, timeout=5)
            send_count += 1
            time.sleep(2)
            if send_count == msg_count:
                break
        logger().info("aws_publish_message_thread completed")


class aws_receive_message_Thread(ThreadBase):
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
            time.sleep(3)
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


class aws_publish_from_raspi_receive_from_wifidut_thread(ThreadBase):
    def __init__(self, wifi_dut, aws_iot_client, topic, message, qos):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.aws_iot_client = aws_iot_client
        self.topic = topic
        self.message = message
        self.qos = qos
        logger().info(f"Topic '{self.topic}'")
        logger().info(f"Message '{self.message}'")
        logger().info(f"QOS '{self.qos}'")

    def run(self):
        i = 0
        for msg in self.message:
            i += 1
            logger().info(f"aws_iot_client is publishing message{i}:'{msg}' on topic:{self.topic}")
            self.aws_iot_client.interfaces.aws_iot.aws_iot_publish(self.topic, msg, qos=self.qos)
            time.sleep(5)


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
    )
]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("iterations", [1])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_connect_sub_publish_C19548(wifi_sniffer, wifi_access_point, wifi_dut, logger, iterations):
    for iter_count in range(iterations):
        logger.info(f"Initiating aws test for iteration:{iter_count + 1}")

        topic_1 = "sdk/test/Python"
        message = []
        for i in range(10):
            message.append(text_generator(size=10))
        logger.info(f"Messages are:{message}")

        capture_filename = "test_C19548"
        join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"Device mac address: {dut_mac_address}")

        logger.info("Initiating aws connect from DUT")
        aws_fail = 1
        for count in range(0, 3):
            try:
                wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
                aws_fail = 0
                break
            except:
                logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
                time.sleep(1)
        assert aws_fail == 0, "Connecting to AWS server is failed"
        logger.info("Connecting to AWS server is successful")
        time.sleep(2)

        subscribe_fail = 1
        for count in range(0, 3):
            try:
                logger.info(f"DUT is Subscribing on topic '{topic_1}'")
                wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
                subscribe_fail = 0
                break
            except:
                logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
                time.sleep(2)
        assert subscribe_fail == 0, "Subscribing to topic is failed"

        count = 0
        for msg in message:
            count += 1
            logger.info(f"Sending message{count} {msg} on topic {topic_1}")
            wifi_dut.interfaces.wifi.aws_iot_publish(topic_1, msg, qos=RS9116AwsQos.QOS0)
            time.sleep(2)

        logger.info("Validating received aws message")
        time.sleep(10)
        events = wifi_dut.interfaces.wifi.get_async_events()
        count = 0
        iot_event = 0
        for event in events:
            if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
                iot_event = 1
                aws_event_qos = event.event_data.qos
                aws_event_topic = event.event_data.topic
                aws_event_payload = event.event_data.payload
                logger.info(
                    f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
                assert topic_1 == aws_event_topic, f"received wrong topic, expected is {topic_1}"
                assert RS9116AwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
                assert message[count] == aws_event_payload, "sent and received messages are not matching"
                count += 1
        assert iot_event == 1, f"published message '{message[count]}' not received on DUT"
        logger.info("aws messages validated successfully")

        logger.info("Unsubscribing from aws topic")
        wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=10)

        logger.info("Initiating aws_iot disconnect")
        wifi_dut.interfaces.wifi.aws_iot_disconnect()

        logger.info("Initiating Wi-Fi disconnection on DUT")
        wifi_dut.interfaces.wifi.leave()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                         f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
        packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

        logger.info("Validating assoc/eapol Packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find association/eapol Packets'

        logger.info("Validating PS Polls with Power Management Bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'

        logger.info(f"Iteration '{iter_count + 1}' completed")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_connect_after_wifi_reconnection_C4053(wifi_sniffer, wifi_access_point, wifi_dut, logger):
    topic_1 = "sdk/test/Python"
    message = []
    for i in range(10):
        message.append(text_generator(size=10))
    logger.info(f"Messages are:{message}")

    capture_filename = "test_C4053"
    logger.info("Joining to AP for first time")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    time.sleep(10)
    logger.info("Initiating wifi leave for first time")
    wifi_dut.interfaces.wifi.leave()

    logger.info("Joining to AP for second time")
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    logger.info("Initiating aws connect from DUT")
    aws_fail = 1
    for count in range(0, 3):
        try:
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail = 0
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
            time.sleep(1)
    assert aws_fail == 0, "Connecting to AWS server is failed"
    logger.info("Connecting to AWS server is successful")
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"

    count = 0
    for msg in message:
        count += 1
        logger.info(f"Sending message{count} {msg} on topic {topic_1}")
        wifi_dut.interfaces.wifi.aws_iot_publish(topic_1, msg, qos=RS9116AwsQos.QOS0)
        time.sleep(2)

    logger.info("Validating received aws message")
    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()
    count = 0
    iot_event = 0
    for event in events:
        if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
            iot_event = 1
            aws_event_qos = event.event_data.qos
            aws_event_topic = event.event_data.topic
            aws_event_payload = event.event_data.payload
            logger.info(
                f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
            assert topic_1 == aws_event_topic, f"received wrong topic, expected is {topic_1}"
            assert RS9116AwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
            assert message[count] == aws_event_payload, "sent and received messages are not matching"
            count += 1
    assert iot_event == 1, f"published message '{message[count]}' not received on DUT"
    logger.info("aws messages validated successfully")

    logger.info("Unsubscribing from aws topic")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=10)

    logger.info("Initiating aws_iot disconnect")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()

    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_server_not_respond_C4062(wifi_sniffer, wifi_access_point, wifi_dut, logger):
    topic_1 = "sdk/test/Python"
    message = []
    for i in range(10):
        message.append(text_generator(size=10))
    logger.info(f"Messages are:{message}")

    capture_filename = "test_C4062"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.aws_iot_connect(hostname="www.google.com", load_cert=False)
    assert exc_info.value.error_code == 0x0021, "DUT sent wrong error code, expected is 0x0021"
    logger.info(f"DUT sent error code '{exc_info.value.error_code}' when server is not responding which is expected")

    logger.info("Initiating aws connect from DUT")
    aws_fail = 1
    for count in range(0, 3):
        try:
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail = 0
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
            time.sleep(1)
    assert aws_fail == 0, "Connecting to AWS server is failed"
    logger.info("Connecting to AWS server is successful")
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"

    count = 0
    for msg in message:
        count += 1
        logger.info(f"Sending message{count} {msg} on topic {topic_1}")
        wifi_dut.interfaces.wifi.aws_iot_publish(topic_1, msg, qos=RS9116AwsQos.QOS0)
        time.sleep(2)

    logger.info("Validating received aws message")
    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()
    count = 0
    iot_event = 0
    for event in events:
        if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
            iot_event = 1
            aws_event_qos = event.event_data.qos
            aws_event_topic = event.event_data.topic
            aws_event_payload = event.event_data.payload
            logger.info(
                f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
            assert topic_1 == aws_event_topic, f"received wrong topic, expected is {topic_1}"
            assert RS9116AwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
            assert message[count] == aws_event_payload, "sent and received messages are not matching"
            count += 1
    assert iot_event == 1, f"published message '{message[count]}' not received on DUT"
    logger.info("aws messages validated successfully")

    logger.info("Unsubscribing from aws topic")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=10)

    logger.info("Initiating aws_iot disconnect")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()

    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
@pytest.mark.parametrize("test_run_time", [1800])
def test_aws_connect_disconnect_sequence_C19552(wifi_sniffer, wifi_access_point, wifi_dut, logger, test_run_time):
    topic_1 = "sdk/test/Python"
    message = []
    for i in range(5):
        message.append(text_generator(size=20))
    logger.info(f"Messages are:{message}")

    capture_filename = "test_C19552"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    sw = Stopwatch()
    logger.info(f"Running the aws connect and disconnect test for '{test_run_time}' seconds")
    while sw.elapsed_sec <= test_run_time:
        time_left = int((test_run_time - sw.elapsed_sec) / 60)
        logger.info(f"Remaining time to complete test is '{time_left}' minutes")
        logger.info("Initiating aws connect from DUT")
        aws_fail = 1
        for count in range(0, 3):
            try:
                wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
                aws_fail = 0
                break
            except:
                logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
                time.sleep(1)
        assert aws_fail == 0, "Connecting to AWS server is failed"
        logger.info("Connecting to AWS server is successful")
        time.sleep(2)

        subscribe_fail = 1
        for count in range(0, 3):
            try:
                logger.info(f"DUT is Subscribing on topic '{topic_1}'")
                wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
                subscribe_fail = 0
                break
            except:
                logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
                time.sleep(2)
        assert subscribe_fail == 0, "Subscribing to topic is failed"

        count = 0
        for msg in message:
            count += 1
            logger.info(f"Sending message{count} {msg} on topic {topic_1}")
            wifi_dut.interfaces.wifi.aws_iot_publish(topic_1, msg, qos=RS9116AwsQos.QOS0)
            time.sleep(5)

        logger.info("Validating received aws message")
        time.sleep(10)
        events = wifi_dut.interfaces.wifi.get_async_events()
        count = 0
        iot_event = 0
        for event in events:
            if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
                iot_event = 1
                aws_event_qos = event.event_data.qos
                aws_event_topic = event.event_data.topic
                aws_event_payload = event.event_data.payload
                logger.info(
                    f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
                assert topic_1 == aws_event_topic, f"received wrong topic, expected is {topic_1}"
                assert RS9116AwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
                assert message[count] == aws_event_payload, "sent and received messages are not matching"
                count += 1
        assert iot_event == 1, f"published message '{message[count]}' not received on DUT"
        logger.info("Received aws message validated successfully")

        logger.info("Unsubscribing from aws topic")
        wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=10)

        logger.info("Initiating aws_iot disconnect")
        wifi_dut.interfaces.wifi.aws_iot_disconnect()

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()

    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


# ########### PR_NEW AWS_TEST CASES CG TEAM #################################
# ############################### PR1 ########################################
# https://jira.silabs.com/browse/WIFI_BT_UTFHELP-773 [clean_session: bool - support is needed in aws_iot_connect method/TestAgent]
# https://jira.silabs.com/browse/WIFI_BT_UTFHELP-786 [Aws_iot: Unable to publish message with size 512 bytes]
# https://jira.silabs.com/browse/WIFI_BT_UTFHELP-857 [ Test agent support required for keep alive periods for aws-mqtt]

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_publish_data_with_different_length_C19553(wifi_sniffer, wifi_access_point, wifi_dut, logger):
    topic_1 = "sdk/test/Python"
    message1 = text_generator(size=1)
    message2 = text_generator(size=10)
    message3 = text_generator(size=100)
    # message4 = text_generator(size=512)
    # message5 = text_generator(size=1000)
    # message6 = text_generator(size=1390)

    message = {"message1": message1, "message2": message2, "message3": message3}
    # message = {"message1": message1, "message2": message2, "message3": message3, "message4": message4, "message5": message5, "message6": message6}
    logger.info(f"Messages are:{message}")

    capture_filename = "test_aws_publish_data_with_different_length_TC19553"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    logger.info("Initiating aws connect from DUT")
    aws_fail = 1
    for count_aws in range(0, 3):
        try:
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail = 0
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count_aws + 1}")
            time.sleep(1)

    assert aws_fail == 0, "Connecting to AWS server is failed"
    logger.info("Connecting to AWS server is successful")
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"

    for message_key, message_value in message.items():
        logger.info(f"message_key:{message_key}, message_value:{message_value}")
        wifi_dut.interfaces.wifi.aws_iot_publish(topic_1, message_value, qos=RS9116AwsQos.QOS0, timeout=5)

        time.sleep(5)
        events = wifi_dut.interfaces.wifi.get_async_events()
        logger.info("Validating received aws message")
        iot_event = 0
        for event in events:
            if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
                iot_event = 1
                aws_event_data = event.event_data
                aws_event_qos = event.event_data.qos
                aws_event_topic = event.event_data.topic
                aws_event_payload = event.event_data.payload
                logger.info(f"Event data: {aws_event_data}")
                logger.info(
                    f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
                assert topic_1 == aws_event_topic, "message is not received on subscribed topic"
                assert RS9116AwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
                assert message_value == aws_event_payload, "sent and received messages are not matching"
        assert iot_event == 1, f"published message '{message_key}:{message_value}' not received on DUT"
        logger.info("aws messages validated successfully")

    logger.info("Unsubscribing from aws topic")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=5)
    logger.info("Initiating aws_iot disconnect")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    time.sleep(5)

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_receive_data_over_subscribed_topic_with_different_lengths_C19554(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                              aws_iot_client, logger):
    topic_1 = "sdk/test/Python"

    message1 = text_generator(size=10)
    message2 = text_generator(size=100)
    # message3 = text_generator(size=500)
    # message4 = text_generator(size=1000)
    # message5 = text_generator(size=1390)

    message = {"message1": message1, "message2": message2}
    # message = {"message1": message1, "message2": message2, "message3": message3, "message4": message4, "message5": message5}
    logger.info(f"Messages are:{message}")

    capture_filename = "test_aws_receive_data_over_subscribed_topic_with_different_lengths_C19554"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    aws_fail_dut = 0
    aws_fail_raspi = 0
    for count_aws in range(0, 3):
        try:
            logger.info("Initiating aws connect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail_dut = 0
            logger.info("Connecting to AWS server from DUT is successful")
            time.sleep(2)
            logger.info("Initiating aws connect from aws_iot_client")
            aws_iot_client.interfaces.aws_iot.aws_iot_connect()
            aws_fail_raspi = 0
            logger.info("Connecting to AWS server from aws_iot_client is successful")
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count_aws + 1}")
            time.sleep(1)
    assert aws_fail_dut == 0, "Connecting to AWS server from DUT is failed"
    assert aws_fail_raspi == 0, "Connecting to AWS server from aws_iot_client is failed"
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"

    for message_key, message_value in message.items():
        logger.info(f"message_key:{message_key}, message_value:{message_value}")
        logger.info(f"aws_iot_client is publishing message '{message_value}' on topic:{topic_1}")
        aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic_1, message_value, qos=0)

        time.sleep(5)
        events = wifi_dut.interfaces.wifi.get_async_events()
        logger.info("Validating received aws messages")
        iot_event = 0
        for event in events:
            if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
                iot_event = 1
                aws_event_data = event.event_data
                aws_event_qos = event.event_data.qos
                aws_event_topic = event.event_data.topic
                aws_event_payload = event.event_data.payload
                logger.info(f"Event data: {aws_event_data}")
                logger.info(
                    f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
                assert topic_1 == aws_event_topic, "message is not received on subscribed topic"
                assert RS9116AwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
                assert message_value == aws_event_payload, "sent and received messages are not matching"
        assert iot_event == 1, f"published message '{message_key}:{message_value}' not received on DUT"
        logger.info("aws messages validated successfully")

    logger.info("Unsubscribing from aws topic from DUT")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=5)
    logger.info("Initiating aws_iot disconnect from DUT")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    time.sleep(1)
    logger.info("Initiating aws_iot disconnect from aws_iot_client")
    aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_tx_after_rejoin_qos0_C19555(wifi_sniffer, wifi_access_point, wifi_dut, switch, logger):
    topic_1 = "sdk/test/Python"
    message = []
    for i in range(10):
        message.append(text_generator(size=10))
    logger.info(f"Messages are:{message}")

    capture_filename = "test_aws_tx_after_rejoin_qos0_C19555"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    logger.info("Initiating aws connect")
    aws_fail = 1
    for count in range(0, 3):
        try:
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail = 0
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
            time.sleep(1)
    assert aws_fail == 0, "Connecting to AWS server is failed"
    logger.info("Connecting to AWS server is successful")
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"

    send_count = 0
    ap_power_off = 0
    while 1:
        if ap_power_off:
            logger.info("Turning off the AP")
            switch.interfaces.pdu_switch.turn_off()
            logger.info("Successfully powered off AP")
            time.sleep(10)
            logger.info("Again turning on the AP")
            switch.interfaces.pdu_switch.turn_on()
            ap_power_off = 0
            logger.info("Waiting for rejoin from DUT")
            time.sleep(100)
            logger.info("Successfully powered on AP")

        # if ap_power_off:
        #     ap_power_off = 0
        #     thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 10, logger))
        #     thread.start()
        #     thread.join()
        #     time.sleep(10)

        msg = message[send_count]
        logger.info(f"Sending message '{msg}' on topic '{topic_1}'")
        wifi_dut.interfaces.wifi.aws_iot_publish(topic_1, msg, qos=RS9116AwsQos.QOS0, timeout=5)
        time.sleep(5)
        send_count = send_count + 1
        if send_count == int(len(message) / 4):
            ap_power_off = 1
        if send_count == int(len(message)):
            break

    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()
    count = 0
    logger.info("Validating received aws messages")
    iot_event = 0
    for event in events:
        if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
            iot_event = 1
            aws_event_data = event.event_data
            aws_event_qos = event.event_data.qos
            aws_event_topic = event.event_data.topic
            aws_event_payload = event.event_data.payload
            logger.info(f"Event data: {aws_event_data}")
            logger.info(
                f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
            assert topic_1 == aws_event_topic, "message is not received on subscribed topic"
            assert RS9116AwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
            assert message[count] == aws_event_payload, "sent and received messages are not matching"
            count += 1
    assert iot_event == 1, f"published message '{message[count]}' not received on DUT"
    logger.info("aws messages validated successfully")
    time.sleep(5)

    logger.info("Unsubscribing from aws topic")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=10)

    logger.info("Initiating aws_iot disconnect")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    time.sleep(5)

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_tx_after_rejoin_qos1_C19556(wifi_sniffer, wifi_access_point, wifi_dut, logger, switch):
    topic_1 = "sdk/test/Python"
    message = []
    for i in range(10):
        message.append(text_generator(size=100))
    logger.info(f"Messages are:{message}")

    capture_filename = "test_aws_tx_after_rejoin_qos1_C19556"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    logger.info("Initiating aws connect")
    aws_fail = 1
    for count in range(0, 3):
        try:
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail = 0
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
            time.sleep(1)
    assert aws_fail == 0, "Connecting to AWS server is failed"
    logger.info("Connecting to AWS server is successful")
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS1, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"

    send_count = 0
    ap_power_off = 0
    while 1:
        if ap_power_off:
            logger.info("Turning off the AP")
            switch.interfaces.pdu_switch.turn_off()
            logger.info("Successfully powered off AP")
            time.sleep(10)
            logger.info("Again turning on the AP")
            switch.interfaces.pdu_switch.turn_on()
            ap_power_off = 0
            time.sleep(100)
            logger.info("Successfully powered on AP")

        # if ap_power_off:
        #     ap_power_off = 0
        #     thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 10, logger))
        #     thread.start()
        #     thread.join()
        #     time.sleep(10)

        msg = message[send_count]
        logger.info(f"Sending message '{msg}' on topic '{topic_1}'")
        wifi_dut.interfaces.wifi.aws_iot_publish(topic_1, msg, qos=RS9116AwsQos.QOS1, timeout=5)
        time.sleep(5)
        send_count = send_count + 1
        if send_count == int(len(message) / 4):
            ap_power_off = 1
        if send_count == int(len(message)):
            break

    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()
    count = 0
    logger.info("Validating received aws messages")
    iot_event = 0
    for event in events:
        if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
            iot_event = 1
            aws_event_data = event.event_data
            aws_event_qos = event.event_data.qos
            aws_event_topic = event.event_data.topic
            aws_event_payload = event.event_data.payload
            logger.info(f"Event data: {aws_event_data}")
            logger.info(
                f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
            assert topic_1 == aws_event_topic, "message is not received on subscribed topic"
            assert RS9116AwsQos.QOS1 == aws_event_qos, "Received wrong QOS. expected is QOS1"
            assert message[count] == aws_event_payload, "sent and received messages are not matching"
            count += 1
    assert iot_event == 1, f"published message '{message[count]}' not received on DUT"
    logger.info("aws messages validated successfully")

    logger.info("Unsubscribing from aws topic")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=10)

    logger.info("Initiating aws_iot disconnect")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    time.sleep(5)

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()

    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


# https://jira.silabs.com/browse/WIFI_BT_UTFHELP-773
# Need test agent change after adding cleanSession flag
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_connection_when_client_id_is_null_C19558(wifi_sniffer, wifi_access_point, wifi_dut, logger):
    capture_filename = "test_aws_connection_when_client_id_is_null_C19558"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    time.sleep(5)

    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'

    logger.info("Initiating aws connect")
    with pytest.raises(Exception) as exc_info:
        wifi_dut.interfaces.wifi.aws_iot_connect(client_id='', clean_session=1, load_cert=False)
    err = 'Incorrect number of arguments'
    assert err in str(exc_info.value), "Expected error not received"
    logger.info(f"aws_iot_connect failed with error: '{err}',which is expected")

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()


# ########### PR2 ###########################
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_tcp_shutdown_C19546(wifi_sniffer, wifi_access_point, wifi_dut,
                                 aws_iot_client, logger):
    topic_1 = "sdk/test/Python"
    message1 = text_generator(size=100)
    message = {"message1": message1}
    logger.info(f"Messages are:{message}")

    capture_filename = "test_aws_tcp_shutdown_C19546"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    aws_fail_dut = 0
    aws_fail_raspi = 0
    for count_aws in range(0, 3):
        try:
            logger.info("Initiating aws connect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail_dut = 0
            logger.info("Connecting to AWS server from DUT is successful")
            time.sleep(2)
            logger.info("Initiating aws connect from aws_iot_client")
            aws_iot_client.interfaces.aws_iot.aws_iot_connect()
            aws_fail_raspi = 0
            logger.info("Connecting to AWS server from aws_iot_client is successful")
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count_aws + 1}")
            time.sleep(1)
    assert aws_fail_dut == 0, "Connecting to AWS server from DUT is failed"
    assert aws_fail_raspi == 0, "Connecting to AWS server from aws_iot_client is failed"
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"
    for message_key, message_value in message.items():
        logger.info(f"message_key:{message_key}, message_value:{message_value}")
        logger.info(f"aws_iot_client is publishing message '{message_value}' on topic:{topic_1}")
        aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic_1, message_value, qos=0)

        time.sleep(5)
        events = wifi_dut.interfaces.wifi.get_async_events()
        logger.info("Validating received aws messages")
        iot_event = 0
        for event in events:
            if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
                iot_event = 1
                aws_event_data = event.event_data
                aws_event_qos = event.event_data.qos
                aws_event_topic = event.event_data.topic
                aws_event_payload = event.event_data.payload
                logger.info(f"Event data: {aws_event_data}")
                logger.info(
                    f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
                assert topic_1 == aws_event_topic, "message is not received on subscribed topic"
                assert RS9116AwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
                assert message_value == aws_event_payload, "sent and received messages are not matching"
        assert iot_event == 1, f"published message '{message_key}:{message_value}' not received on DUT"
        logger.info("aws messages validated successfully")

    logger.info("Initiating AWS shutdown")
    wifi_dut.interfaces.wifi.close_sockets()
    logger.info("AWS shutdown success")

    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_rx_over_subscribed_topic_after_rejoin_qos1_C19559(wifi_sniffer, wifi_access_point, wifi_dut,
                                                               aws_iot_client, switch, logger):
    topic_1 = "sdk/test/Python"
    message = []
    for i in range(10):
        message.append(text_generator(size=100))
    logger.info(f"Messages are:{message}")

    capture_filename = "test_C19559"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    aws_fail_dut = 0
    aws_fail_raspi = 0
    for count_aws in range(0, 3):
        try:
            logger.info("Initiating aws connect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail_dut = 0
            logger.info("Connecting to AWS server from DUT is successful")
            time.sleep(2)
            logger.info("Initiating aws connect from aws_iot_client")
            aws_iot_client.interfaces.aws_iot.aws_iot_connect()
            aws_fail_raspi = 0
            logger.info("Connecting to AWS server from aws_iot_client is successful")
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count_aws + 1}")
            time.sleep(1)
    assert aws_fail_dut == 0, "Connecting to AWS server from DUT is failed"
    assert aws_fail_raspi == 0, "Connecting to AWS server from aws_iot_client is failed"
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS1, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"

    send_count = 0
    ap_power_off = 0
    while 1:

        if ap_power_off:
            logger.info("Turning off the AP")
            switch.interfaces.pdu_switch.turn_off()
            logger.info("Successfully powered off AP")
            time.sleep(10)
            logger.info("Again turning on the AP")
            switch.interfaces.pdu_switch.turn_on()
            ap_power_off = 0
            time.sleep(100)
            logger.info("Successfully powered on AP")

        # if ap_power_off:
        #     ap_power_off = 0
        #     thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 10, logger))
        #     thread.start()
        #     thread.join()
        #     time.sleep(10)

        msg = message[send_count]
        logger.info(f"aws_iot_client is publishing message '{msg}' on topic:{topic_1}")
        aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic_1, msg, qos=1)
        time.sleep(5)
        send_count = send_count + 1
        if send_count == int(len(message) / 4):
            ap_power_off = 1
        if send_count == int(len(message)):
            break

    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()
    count = 0
    logger.info("Validating received aws messages")
    iot_event = 0
    for event in events:
        if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
            iot_event = 1
            aws_event_data = event.event_data
            aws_event_qos = event.event_data.qos
            aws_event_topic = event.event_data.topic
            aws_event_payload = event.event_data.payload
            logger.info(f"Event data: {aws_event_data}")
            logger.info(
                f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
            assert topic_1 == aws_event_topic, "message is not received on subscribed topic"
            assert RS9116AwsQos.QOS1 == aws_event_qos, "Received wrong QOS. expected is QOS1"
            assert message[count] == aws_event_payload, "sent and received messages are not matching"
            count += 1
    assert iot_event == 1, f"published message '{message[count]}' not received on DUT"
    logger.info("aws messages validated successfully")

    logger.info("Unsubscribing from aws topic from DUT")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=10)

    logger.info("Initiating aws_iot disconnect from DUT")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    time.sleep(1)
    logger.info("Initiating aws_iot disconnect from aws_iot_client")
    aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()

    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_publish_message_in_thread1_and_receive_message_in_thread2_C19566(wifi_sniffer, wifi_access_point,
                                                                              wifi_dut, aws_iot_client, logger):
    topic_1 = "sdk/test/Python"
    message = []
    for i in range(10):
        message.append(text_generator(size=10))
    logger.info(f"Messages are:{message}")

    capture_filename = "test_C19566"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    aws_fail_dut = 0
    aws_fail_raspi = 0
    for count_aws in range(0, 3):
        try:
            logger.info("Initiating aws connect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail_dut = 0
            logger.info("Connecting to AWS server from DUT is successful")
            time.sleep(2)
            logger.info("Initiating aws connect from aws_iot_client")
            aws_iot_client.interfaces.aws_iot.aws_iot_connect()
            aws_fail_raspi = 0
            logger.info("Connecting to AWS server from aws_iot_client is successful")
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count_aws + 1}")
            time.sleep(1)
    assert aws_fail_dut == 0, "Connecting to AWS server from DUT is failed"
    assert aws_fail_raspi == 0, "Connecting to AWS server from aws_iot_client is failed"
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"aws_iot_client is subscribing on topic '{topic_1}'")
            aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS1)
            time.sleep(4)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"
    logger.info("Subscribing to topic is successful")

    t1 = aws_publish_message_Thread(wifi_dut, topic_1, message, qos=RS9116AwsQos.QOS1)
    t2 = aws_receive_message_Thread(aws_iot_client, topic_1, message, qos=RS9116AwsQos.QOS1)

    logger.info("aws_publish_message_thread + aws_receive_message_thread execution starts....")
    t1.start()
    t2.start()

    t1.wait_for_exit(True)
    t2.wait_for_exit(True)

    logger.info("Unsubscribing from aws topic from aws_iot_client")
    aws_iot_client.interfaces.aws_iot.aws_iot_unsubscribe(topic_1)
    time.sleep(2)

    logger.info("Initiating aws_iot disconnect from DUT")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    time.sleep(1)
    logger.info("Initiating aws_iot disconnect from aws_iot_client")
    aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()

    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("test_run_time", [1800])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_publish_a_message_on_the_topic_for_every_10_minutes_C19567(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                        logger, test_run_time):
    topic_1 = "sdk/test/Python"
    message = []
    for i in range(5):
        message.append(text_generator(size=20))
    logger.info(f"Messages are:{message}")

    capture_filename = "test_C19567"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    logger.info("Initiating aws connect from DUT")
    aws_fail = 1
    for count_aws in range(0, 3):
        try:
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail = 0
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count_aws + 1}")
            time.sleep(1)

    assert aws_fail == 0, "Connecting to AWS server is failed"
    logger.info("Connecting to AWS server is successful")
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"

    sw = Stopwatch()
    while sw.elapsed_sec < test_run_time:
        for msg in message:
            logger.info(f"Sending message '{msg}' on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_publish(topic_1, msg, qos=RS9116AwsQos.QOS0, timeout=5)
            time.sleep(2)

        logger.info("Validating received aws messages")
        time.sleep(10)
        events = wifi_dut.interfaces.wifi.get_async_events()
        count = 0
        iot_event = 0
        for event in events:
            if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
                iot_event = 1
                aws_event_data = event.event_data
                aws_event_qos = event.event_data.qos
                aws_event_topic = event.event_data.topic
                aws_event_payload = event.event_data.payload
                logger.info(f"Event data: {aws_event_data}")
                logger.info(
                    f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
                assert topic_1 == aws_event_topic, "message is not received on subscribed topic"
                assert RS9116AwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
                assert message[count] == aws_event_payload, "sent and received messages are not matching"
                count += 1
        assert iot_event == 1, f"published message '{message[count]}' not received on DUT"
        logger.info("aws messages validated successfully")

        logger.info("DUT is going to sleep for 10 minutes")
        time.sleep(600)
        logger.info("Again publishing aws message from DUT after 10 minutes of sleep")

    logger.info("Unsubscribing from aws topic")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=5)

    logger.info("Initiating aws_iot disconnect")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    time.sleep(5)

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


# ################################# PR3 #####################################
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("iterations", [1])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_receive_functionality_while_receiving_100_mqtt_messages_continuously_C19561(wifi_sniffer,
                                                                                         wifi_access_point, wifi_dut,
                                                                                         aws_iot_client, logger,
                                                                                         iterations):
    topic_1 = "mytesttopic/1"
    # 100 messages of 300 bytes of random data
    message = []
    for i in range(100):
        message.append(text_generator(size=300))
    logger.info(f"Messages are:{message}")

    capture_filename = "test_C19561"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")
    aws_fail_dut = 0
    aws_fail_raspi = 0
    for count_aws in range(0, 3):
        try:
            logger.info("Initiating aws connect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail_dut = 0
            logger.info("Connecting to AWS server from DUT is successful")
            time.sleep(2)
            logger.info("Initiating aws connect from aws_iot_client")
            aws_iot_client.interfaces.aws_iot.aws_iot_connect()
            aws_fail_raspi = 0
            logger.info("Connecting to AWS server from aws_iot_client is successful")
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count_aws + 1}")
            time.sleep(1)
    assert aws_fail_dut == 0, "Connecting to AWS server from DUT is failed"
    assert aws_fail_raspi == 0, "Connecting to AWS server from aws_iot_client is failed"
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"

    for iter_count in range(iterations):
        logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
        i = 0
        for msg in message:
            i += 1
            logger.info(f"aws_iot_client is publishing message{i}:'{msg}' on topic:{topic_1}")
            aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic_1, msg, qos=0)
            time.sleep(3)

        time.sleep(10)
        events = wifi_dut.interfaces.wifi.get_async_events()
        logger.info("Validating received aws messages")
        count = 0
        iot_event = 0
        for event in events:
            if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
                iot_event += 1
                aws_event_data = event.event_data
                aws_event_qos = event.event_data.qos
                aws_event_topic = event.event_data.topic
                aws_event_payload = event.event_data.payload
                logger.info(f"Event data: {aws_event_data}")
                logger.info(
                    f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
                assert topic_1 == aws_event_topic, "message is not received on subscribed topic"
                assert RS9116AwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
                assert message[count] == aws_event_payload, "sent and received messages are not matching"
                count += 1
        assert iot_event == 100, f"published message '{message[count]}' not received on DUT"
        logger.info("aws messages validated successfully")
        logger.info(f"Iteration '{iter_count + 1}' completed")

    logger.info("Unsubscribing from aws topic")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=5)

    logger.info("Initiating aws_iot disconnect")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    time.sleep(5)

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()

    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("total_bytes", [20])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_receive_100_mqtt_messages_over_2_subscribed_topics_C19563(wifi_sniffer, wifi_access_point,
                                                                       wifi_dut, aws_iot_client, logger,
                                                                       total_bytes):
    topic_1 = "mytesttopic/1"
    topic_2 = "mytesttopic/2"
    message = []
    for i in range(100):
        message.append(text_generator(size=total_bytes))
    logger.info(f"Messages are:{message}")

    capture_filename = "test_C19563"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")
    aws_fail_dut = 0
    aws_fail_raspi = 0
    for count_aws in range(0, 3):
        try:
            logger.info("Initiating aws connect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail_dut = 0
            logger.info("Connecting to AWS server from DUT is successful")
            time.sleep(2)
            logger.info("Initiating aws connect from aws_iot_client")
            aws_iot_client.interfaces.aws_iot.aws_iot_connect()
            aws_fail_raspi = 0
            logger.info("Connecting to AWS server from aws_iot_client is successful")
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count_aws + 1}")
            time.sleep(1)
    assert aws_fail_dut == 0, "Connecting to AWS server from DUT is failed"
    assert aws_fail_raspi == 0, "Connecting to AWS server from aws_iot_client is failed"
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_2}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_2, qos=RS9116AwsQos.QOS1, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_2}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"

    qos0_thread = aws_publish_from_raspi_receive_from_wifidut_thread(wifi_dut, aws_iot_client, topic_1, message, 0)
    qos1_thread = aws_publish_from_raspi_receive_from_wifidut_thread(wifi_dut, aws_iot_client, topic_2, message, 1)

    qos0_thread.start()
    time.sleep(5)
    qos1_thread.start()

    qos0_thread.wait_for_exit(True)
    qos1_thread.wait_for_exit(True)

    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()
    logger.info("Validating received aws messages")
    iot_event = 0
    qos0_count = 0
    qos1_count = 0
    for event in events:
        if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
            aws_event_qos = event.event_data.qos
            aws_event_topic = event.event_data.topic
            aws_event_payload = event.event_data.payload
            if aws_event_qos == RS9116AwsQos.QOS0:
                logger.info(
                    f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
                assert topic_1 == aws_event_topic, f"Received wrong topic. expected is topic1:{topic_1}"
                assert aws_event_qos == RS9116AwsQos.QOS0, "Received wrong QOS. expected is QOS0"
                assert message[qos0_count] == aws_event_payload, "sent and received messages are not matching"
                qos0_count += 1
            else:
                logger.info(
                    f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
                assert topic_2 == aws_event_topic, f"Received wrong topic. expected is topic2:{topic_2}"
                assert aws_event_qos == RS9116AwsQos.QOS1, "Received wrong QOS. expected is QOS0"
                assert message[qos1_count] == aws_event_payload, "sent and received messages are not matching"
                qos1_count += 1
            iot_event += 1
    assert iot_event == 200, f"some of published message not received on DUT"
    logger.info("aws messages validated successfully")

    logger.info("Unsubscribing from aws topic1")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=5)

    logger.info("Unsubscribing from aws topic2")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_2, timeout=5)

    logger.info("Initiating aws_iot disconnect")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    time.sleep(5)

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()

    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("iterations", [2])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_check_rejoin_failure_functionality_of_dut_C19549(wifi_sniffer, wifi_access_point, wifi_dut, switch,
                                                              logger, iterations):
    topic_1 = "sdk/test/Python"
    message = []
    for i in range(5):
        message.append(text_generator(size=10))
    logger.info(f"Messages are:{message}")

    capture_filename = "test_C19549"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    for i in range(iterations):
        logger.info(f"Initiating aws connect for iteration:{i + 1}")
        aws_fail = 1
        for count in range(0, 3):
            try:
                wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
                aws_fail = 0
                break
            except:
                logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
                time.sleep(1)
        assert aws_fail == 0, "Connecting to AWS server is failed"
        logger.info("Connecting to AWS server is successful")
        time.sleep(2)

        subscribe_fail = 1
        for count in range(0, 3):
            try:
                logger.info(f"DUT is Subscribing on topic '{topic_1}'")
                wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
                subscribe_fail = 0
                break
            except:
                logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
                time.sleep(2)
        assert subscribe_fail == 0, "Subscribing to topic is failed"

        send_count = 0
        while 1:
            msg = message[send_count]
            logger.info(f"Sending message '{msg}' on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_publish(topic_1, msg, qos=RS9116AwsQos.QOS0, timeout=5)
            send_count += 1
            time.sleep(3)
            if send_count == int(len(message)):
                break

        time.sleep(10)
        events = wifi_dut.interfaces.wifi.get_async_events()
        count = 0
        logger.info("Validating received aws messages")
        iot_event = 0
        for event in events:
            if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
                iot_event = 1
                aws_event_data = event.event_data
                aws_event_qos = event.event_data.qos
                aws_event_topic = event.event_data.topic
                aws_event_payload = event.event_data.payload
                logger.info(f"Event data: {aws_event_data}")
                logger.info(
                    f"QOS received: '{aws_event_qos}', aws topic received: '{aws_event_topic}', aws message received:'{aws_event_payload}'")
                assert topic_1 == aws_event_topic, "message is not received on subscribed topic"
                assert RS9116AwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
                assert message[count] == aws_event_payload, "sent and received messages are not matching"
                count += 1
        assert iot_event == 1, f"published message '{message[count]}' not received on DUT"
        logger.info("aws messages validated successfully")

        logger.info("Turning off the AP")
        switch.interfaces.pdu_switch.turn_off()
        logger.info("Successfully powered off AP")
        time.sleep(10)

        # logger.info("Disabling Wireless in AP")
        # wifi_access_point.interfaces.wifi.stop_ap()
        # time.sleep(5)
        # logger.info("Disabled Wireless in AP")

        logger.info("Checking for rejoin fail event from dut, this may take some time....")
        sw = Stopwatch()
        rejoin_msg = 0
        while sw.elapsed_sec <= 200:
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.RejoinError:
                        rejoin_msg = 1
            if rejoin_msg:
                break
        logger.info(f"Elapsed time to get rejoin_error is: '{int(sw.elapsed_sec)}' sec")
        assert rejoin_msg == 1, "rejoin fail event not found even after AP is switched off"

        wifi_dut.interfaces.wifi.reset_soft()
        wifi_dut.interfaces.wifi.init()

        logger.info("Again turning on the AP")
        switch.interfaces.pdu_switch.turn_on()
        time.sleep(60)
        logger.info("Successfully powered on AP")

        # logger.info("Enabling Wireless in AP")
        # wifi_access_point.interfaces.wifi.start_ap()
        # time.sleep(10)

        wifi_dut.interfaces.wifi.rejoin(rejoin_max=10, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
        logger.info("Joining to the Wifi Access Point")
        for count in range(1, 3):
            join_fail = 1
            ip_fail = 1
            try:
                wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
                join_fail = 0
                logger.info("DUT gets ipaddress through DHCP ")
                wifi_dut.interfaces.wifi.start_ip(timeout=60)
                ip_fail = 0
                break
            except:
                logger.info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
            assert join_fail == 0, "Joining to the AP is failed"
            assert ip_fail == 0, "ip setting in DUT has failed"
        logger.info(f"Iteration '{i + 1}' completed")

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


# @pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("iterations", [1])
@pytest.mark.parametrize("publish_len, total_bytes", [(490, 1024000)])  # 493 is max limit
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_data_integrity_check_after_receiving_1mb_of_data_over_mqtt_C19562(wifi_sniffer, wifi_access_point,
                                                                               wifi_dut,
                                                                               aws_iot_client, logger, publish_len,
                                                                               total_bytes, iterations):
    current_time = time.time()
    topic_1 = "mytesttopic/1"

    capture_filename = "test_C19562"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")
    aws_fail_dut = 0
    aws_fail_raspi = 0
    for count_aws in range(0, 3):
        try:
            logger.info("Initiating aws connect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail_dut = 0
            logger.info("Connecting to AWS server from DUT is successful")
            time.sleep(2)
            logger.info("Initiating aws connect from aws_iot_client")
            aws_iot_client.interfaces.aws_iot.aws_iot_connect()
            aws_fail_raspi = 0
            logger.info("Connecting to AWS server from aws_iot_client is successful")
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count_aws + 1}")
            time.sleep(1)
    assert aws_fail_dut == 0, "Connecting to AWS server from DUT is failed"
    assert aws_fail_raspi == 0, "Connecting to AWS server from aws_iot_client is failed"
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"DUT is Subscribing on topic '{topic_1}'")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0, timeout=5)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"

    data = text_generator(size=total_bytes)
    file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    tx_file = "./reports/" + capture_filename + "_tx_file_" + file_time_stamp + ".txt"
    with open(tx_file, "w") as temp:
        temp.write(data)

    since_time = 0
    msgs = []
    recv_count = 0
    for iter_count in range(iterations):
        logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
        with open(tx_file, "r") as temp:
            while 1:
                recv_fail = 0
                data = temp.read(publish_len)
                if data == '':
                    break
                else:
                    for retry_count in range(10):
                        try:
                            logger.info(f"aws_iot_client is publishing message:'{data}' on topic:{topic_1}")
                            aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic_1, data, qos=0)
                            time.sleep(3)
                            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                            logger.info("Fetching received aws messages")
                            recv_count = 0
                            for event in events:
                                if event.event_type == RS9116AsyncEventType.AWSIoTMQTTMessage:
                                    aws_event_qos = event.event_data.qos
                                    aws_event_topic = event.event_data.topic
                                    aws_event_payload = event.event_data.payload
                                    since_time = event.timestamp + 1
                                    assert topic_1 == aws_event_topic, "received topic is not matching with subscribed topic"
                                    assert RS9116AwsQos.QOS0 == aws_event_qos, "Received wrong QOS. expected is QOS0"
                                    assert data == aws_event_payload, "sent and received messages are not matching"
                                    recv_fail = 0
                                    recv_count = 1
                                if event.event_type == RS9116AsyncEventType.TCP_REMOTE_TERMINATE:
                                    logger.info("tcp socket is closed...waiting for rejoin from DUT")
                                    since_time = event.timestamp + 1
                                    time.sleep(200)
                            assert recv_count == 1, "Published message not received on DUT"
                            msgs.append(aws_event_payload)
                        except:
                            recv_fail = 1
                            time.sleep(10)
                            logger.info(f"Published message not received on DUT-->retry_count:{retry_count + 1}")
                        if recv_count:
                            break
                    if recv_fail:
                        break

        logger.info("Validating 1mb of data by comparing tx_file an rx_file")
        file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
        rx_file = "./reports/" + capture_filename + f"_rx_file_{iter_count}" + file_time_stamp + ".txt"
        if len(msgs):
            with open(rx_file, "w") as recv:
                for data in msgs:
                    recv.write(data)
        if not os.path.exists(rx_file):
            logger.info("No aws data received at receiver")
        result = filecmp.cmp(tx_file, rx_file, shallow=False)
        assert result, "Data loss observed, Contents of tx file and rx file not matched"
        logger.info("Contents of tx_file and rx_file are same")
        logger.info(f"Iteration '{iter_count + 1}' completed")

    logger.info("Unsubscribing from aws topic")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1, timeout=10)

    logger.info("Initiating aws_iot disconnect")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    time.sleep(5)

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()

    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'


# @pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("iterations", [1])
@pytest.mark.parametrize("publish_len, total_bytes", [(90, 102400)])  # 100 is max limit 1024000-filesize
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
def test_aws_data_integrity_check_after_sending_1mb_of_data_over_mqtt_C19564(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                             aws_iot_client, logger, publish_len,
                                                                             total_bytes, iterations):
    current_time = time.time()
    topic_1 = "mytesttopic/1"

    capture_filename = "test_C19564"
    join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    aws_fail_dut = 0
    aws_fail_raspi = 0
    for count_aws in range(0, 3):
        try:
            logger.info("Initiating aws connect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail_dut = 0
            logger.info("Connecting to AWS server from DUT is successful")
            time.sleep(2)
            logger.info("Initiating aws connect from aws_iot_client")
            aws_iot_client.interfaces.aws_iot.aws_iot_connect()
            aws_fail_raspi = 0
            logger.info("Connecting to AWS server from aws_iot_client is successful")
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count_aws + 1}")
            time.sleep(1)
    assert aws_fail_dut == 0, "Connecting to AWS server from DUT is failed"
    assert aws_fail_raspi == 0, "Connecting to AWS server from aws_iot_client is failed"
    time.sleep(2)

    subscribe_fail = 1
    for count in range(0, 3):
        try:
            logger.info(f"aws_iot_client is subscribing on topic '{topic_1}'")
            aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(topic_1, qos=RS9116AwsQos.QOS0)
            time.sleep(4)
            subscribe_fail = 0
            break
        except:
            logger.info(f"Subscribing on topic '{topic_1}' failed. retry count->{count + 1}")
            time.sleep(2)
    assert subscribe_fail == 0, "Subscribing to topic is failed"
    logger.info("Subscribing to topic is successful")

    data = text_generator(size=total_bytes)
    file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    tx_file = "./reports/" + capture_filename + "_tx_file_" + file_time_stamp + ".txt"
    with open(tx_file, "w") as temp:
        temp.write(data)

    for iter_count in range(iterations):
        logger.info(f"Initiating aws test for iteration:{iter_count + 1}")
        with open(tx_file, "r") as temp:
            while 1:
                data = temp.read(publish_len)
                if data == '':
                    break
                else:
                    for count in range(3):
                        try:
                            logger.info(f"DUT is publishing message:'{data}' on topic:{topic_1}")
                            wifi_dut.interfaces.wifi.aws_iot_publish(topic_1, data, qos=RS9116AwsQos.QOS0, timeout=5)
                            time.sleep(5)
                            break
                        except:
                            logger.info(f"Publishing message is failed. retry count->{count + 1}")

        time.sleep(10)
        recv_messages = aws_iot_client.interfaces.aws_iot.get_received_messages()
        logger.info("Fetching received aws messages")
        msgs = []
        for msg in recv_messages:
            msgs.append(msg.payload.decode())
            assert msg.topic == topic_1, "Received wrong topic in aws_iot_client"
            assert msg.qos == RS9116AwsQos.QOS0, "Received wrong qos in aws_iot_client"

        logger.info("Validating 1mb of data by comparing tx_file an rx_file")
        file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
        rx_file = "./reports/" + capture_filename + f"_rx_file_{iter_count}" + file_time_stamp + ".txt"
        if len(msgs):
            with open(rx_file, "w") as recv:
                for data in msgs:
                    recv.write(data)
        if not os.path.exists(rx_file):
            logger.info("No aws data received at receiver")
        result = filecmp.cmp(tx_file, rx_file, shallow=False)
        assert result, "Data loss observed, Contents of tx file and rx file not matched"
        logger.info("Contents of tx_file and rx_file are same")
        logger.info(f"Iteration '{iter_count + 1}' completed")

    logger.info("Unsubscribing from aws topic from aws_iot_client")
    aws_iot_client.interfaces.aws_iot.aws_iot_unsubscribe(topic_1)
    time.sleep(2)

    logger.info("Initiating aws_iot disconnect from DUT")
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    time.sleep(1)
    logger.info("Initiating aws_iot disconnect from aws_iot_client")
    aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()

    logger.info("Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol ' \
                     f'and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    logger.info("Validating assoc/eapol Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association/eapol Packets'

    logger.info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'

