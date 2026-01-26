import time
import pytest
import string
import random
from retry import retry
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xJoinFeatureBitMap,
    Si91xAwsQos
)
from AWSIoTPythonSDK.core.protocol.internal.clients import ClientStatus
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs

from datetime import datetime, date
import re
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from test_sta_ble_sdk import BleThreadFunctionality, SnifferValidationProcess, ScanTime_JoinTime, WifiJoinThread
from utf.utils.stopwatch import Stopwatch

from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import (BodySensorLocationCharacteristic,
                                                                                HeartRateControlPointCharacteristic,
                                                                                HeartRateMeasurementCharacterstic)
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertLevelCharacteristic
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import threading
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs



def logger():
    return get_logger(__name__)

def text_generator(size=2000):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


class SnifferValidationProcess:
    def __init__(
            self,
            wifi_sniffer=None,
            wifi_access_point=None,
            dut_mac_address=None,
            ap_mac_address=None,
            sniffer_filter=None,
            sl_collections=None,
    ):
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.sl_collections = sl_collections
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def sniffer_validation_join(self, tcp_ip_bypass=False):
        power_save = True
        self.sl_collections.join_sniffer_validation(
            self.wifi_access_point,
            self.wifi_sniffer,
            self.dut_mac_address,
            self.ap_mac_address,
            self.sniffer_filter,
            power_save=self.power_save,
        )
        if not tcp_ip_bypass:
            self.sniffer_validation_powersave()

    def sniffer_validation_beacon(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.ap_mac_address,
                                                                                        filter_name="beacon")
        logger().info(f"Validating beacon frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find beacons packets in sniffer from new AP Channel"

    def sniffer_validation_deauth(self):
        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address, filter_name="deauthentication"
            )
        )
        logger().info(f"Validating deauthentication frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find deauthentication packets in sniffer"

    def sniffer_validation_scan(self):

        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address, filter_name="probe_request"
            )
        )
        logger().info(f"Validating Probe req(Broadcast)")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find probe_request packets in sniffer"

    def sniffer_validation_powersave(self):
        if self.power_save:
            packet_filter1 = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_mac_address, filter_name="ps_poll"
                )
            )
            logger().info(f"Validating PS-POLL frames ")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter1
            )["packet_count"], "Sniffer: Unable to find ps poll packets in sniffer"
            packet_filter2 = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_mac_address,
                    da_addr=self.ap_mac_address,
                    filter_name="qos_data_more_data",
                )
            )
            logger().info(f"Validating QOS data frames with more data bit set")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter2
            )[
                "packet_count"
            ], "Sniffer: Unable to find QOS data frames with more data bit set in sniffer"



class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi scan ,connectivity ,powersave ,data transfer"""

    def __init__(
            self,
            http_server = None,
            wifi_sniffer=None,
            wifi_dut=None,
            wifi_access_point=None,
            testcase=None,
            wifi_client=None,
            test_type=None,
            sl_collections=None,
            ping_count=None,
            sniffer_filter=None,
            timeout=60,
            skip_scan=False,
            test_case_id=None,
            eap_type=None,
            aws_iot_client = None,
            utf_constants = None,
            messages = None,
            qos=Si91xAwsQos.QOS1,
    ):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.http_server = http_server
        self.utf_constants = utf_constants
        self.aws_iot_client = aws_iot_client
        self.messages = messages
        self.wifi_client = wifi_client
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.timeout = timeout
        self.skip_scan = skip_scan
        self.test_case_id = test_case_id
        self.eap_type = eap_type
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def scan(self):

        logger().info("Initiating wlan scan")
        # enables the scan in dut on channel
        scan_status, scan_results = self.sl_collections.scan(self.wifi_dut, scan_status=False, retry_count=3,
                                                             channel=0)
        logger().info(f"scan results : {scan_results}")
        assert len(scan_results) > 0, "scan failed"

    def join_to_ap(self):

        if not self.wifi_dut.interfaces.wifi.associated:

            self.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                power_save=self.power_save,
                associated=self.wifi_dut.interfaces.wifi.associated,
                retry_count=3,
                ping_before_power_save=True,
                ping_after_power_save=True,
                ping_count=self.ping_count,
                skip_scan=self.skip_scan
            )
            self.dut_mac_address = self.dut_addr["dut_mac_address"]
            logger().info(
                f"*****************DUT_MAC_ADDR : {self.dut_mac_address}*********************"
            )
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {self.ap_mac_address}")
            return self.dut_addr

    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

    def sniffer_validation_join(self):
        sniff_obj = SnifferValidationProcess(
            wifi_sniffer=self.wifi_sniffer,
            wifi_access_point=self.wifi_access_point,
            dut_mac_address=self.dut_mac_address,
            ap_mac_address=self.ap_mac_address,
            sniffer_filter=self.sniffer_filter,
            sl_collections=self.sl_collections,
        )
        sniff_obj.sniffer_validation_join()

    def get_firmware_status(self):
        self.wifi_dut.interfaces.wifi.reset()
        time.sleep(30)
        logger().info("Initialising DUT after the reset....")
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        self.wifi_dut.interfaces.wifi.init(load_certificate=False)
        self.wifi_dut.interfaces.wifi.initialize_thread()
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_after_upgrade = self.wifi_dut.interfaces.wifi.version()
        self.wifi_dut.interfaces.wifi.inited = False
        time.sleep(5)
        return fw_after_upgrade

    ## aws code
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

    ## aws code

    def run(self):
        if self.test_case_id == "778128":
            try:
                for i in range(0, 3):
                    self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=self.wifi_access_point.interfaces.wifi.ssid)
                    i = i+1
                if self.eap_type == "tls" or self.eap_type == "ttls" or self.eap_type == "peap" or self.eap_type == "fast" \
                        or self.eap_type == "peapsafe1" or self.eap_type == "peapsafe2":
                    self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                  passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                  security="wpa2_enterprise", uid="user1", enc=self.eap_type, channel=8)
                    self.wifi_dut.interfaces.wifi.start_ip()
            except Exception as e:
                self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)
                logger().info(f"Exception during EAP connection: {e}")

        elif self.test_case_id in "778129":
                try:
                    self.join_to_ap()
                    upgrade_thread = FirmwareUpgradeThread(
                        wifi_dut=self.wifi_dut,
                        wifi_client=self.wifi_client,
                    )
                    upgrade_thread.start()
                    upgrade_thread.wait_for_exit()
                except Exception as e:
                    logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
                    raise e

        elif self.test_case_id == "778130":
                try:
                    logger().info(f" printing test case id : {self.test_case_id}")
                    self.join_to_ap()
                    if self.messages is None:
                        self.messages = []
                        for i in range(10):
                            self.messages.append(text_generator(size=10))
                        logger().info(f"Messages are:{self.messages}")
                    logger().info("Initiating aws connect from DUT")
                    client_id = 'client_c19548'
                    logger().info (f"Client ID for AWS connection is : {client_id}")
                    topic = "topic_c19548"
                    logger().info(f"Topic for AWS connection is : {topic}")
                    # iterations = self.utf_constants.get('iter_count')
                    logger().info("Initiating aws connect from DUT")
                    assert self.connect_to_aws_server_from_dut(self.wifi_dut,
                                                                  client_id), "Failed to connect aws server from DUT"
                    logger().info("Connecting to AWS server from DUT is successful")
                    logger().info (f"subscribe_from_dut")
                    self.subscribe_from_dut(self.wifi_dut, topic, qos=Si91xAwsQos.QOS0)
                    logger().info ("connect to AWS server from raspi")
                    self.connect_to_aws_server_from_raspi(self.aws_iot_client)
                    logger().info (f"subscribe_from_raspi")
                    self.subscribe_from_raspi(self.aws_iot_client, topic, qos=Si91xAwsQos.QOS0)
                    logger().info("publishing started thread from DUT to raspi")
                    for count, msg in enumerate(self.messages):
                        logger().info("inside count msg loop")
                        logger().info(
                            f"\nDUT is publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS0}'"
                            f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
                        self.publish_from_dut(self.wifi_dut, topic, msg, qos=Si91xAwsQos.QOS0)
                        time.sleep(3)
                    self.validate_aws_messages_from_raspi(self.aws_iot_client, topic, Si91xAwsQos.QOS0, self.messages)


                except Exception as e:
                    logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
                    raise e
        else:
            logger().info(f" printing test case id : {self.test_case_id}")
            logger().info("wlan join thread entered in else block code")
            self.join_to_ap()

class FirmwareUpgradeThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.host_ip = None
        self.fw_before_upgrade = None
        self.fw_after_upgrade = None
        self.time_duration = None

    def get_firmware_status(self):
        self.wifi_dut.interfaces.wifi.reset()
        time.sleep(30)
        logger().info("Initialising DUT after the reset....")
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        self.wifi_dut.interfaces.wifi.init(load_certificate=False)
        # self.wifi_dut.interfaces.wifi.initialize_thread()
        # self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_after_upgrade = self.wifi_dut.interfaces.wifi.version()
        self.wifi_dut.interfaces.wifi.inited = False
        time.sleep(5)
        return fw_after_upgrade

    def run(self):
        try:
            logger().info("performing firmware upgrade....")
            self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"host ip is {self.host_ip}")
            self.fw_before_upgrade = self.wifi_dut.interfaces.wifi.version()
            logger().info(f" ***** FW before upgrade: {self.fw_before_upgrade} *****")
            self.wifi_dut.interfaces.wifi.firmware_upgrade(ip_address=self.host_ip, host_name=self.host_ip)
            time.sleep(5)
            start_time = time.time()
            logger().info(f" start firmware upgrade: {start_time}")
            finish_time = time.time()
            logger().info(f"firmware upgraded : {finish_time}")
            self.time_duration = (finish_time - start_time)
            logger().info(f"Time taken to upgrade firmware is: {self.time_duration}")

            if self.time_duration > 40:
                logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {self.time_duration}")
            else:
                logger().info(f"time taken to upgrade firmware using http otaf {self.time_duration} seconds")
            logger().info(f"\n ***firmware versions not matched after loading firmware through otaf \n")
            logger().info("Stop Sniffer finally")
            self.fw_after_upgrade = self.get_firmware_status()
            time.sleep(2)
            logger().info(f"\n\n ***firmware versions before otaf:{self.fw_before_upgrade}"
                          f" firmware version after loading through otaf :{self.fw_after_upgrade}")
            assert self.fw_before_upgrade != self.fw_after_upgrade, f"firmware versions should not match after loading firmware through otaf"
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
            raise e


class BleThread(ThreadBase):
    def __init__(
            self,
            wifi_dut=None,
            ble_client=None,
            ble_test_type=None,
            sl_collections=None,
            ble_scan_type=1,
            ble_scan_filter_type=0,
            ble_pairing=0,
            dev_state=8,
            gatt=True,
            service_class=None,
            conn_interval=200,
            char_path=None, char_uid=None, data=None,
            data_length=20, data_duration=60, periodic_delay=1, service_uid=None,
            address=None,
            service_uuid=None,
            char_uuid=None,
            characteristic=None,
            bond_info=0,
            ble_scan_interval=None,
            ble_scan_window=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_scan_interval = ble_scan_interval
        self.ble_scan_window = ble_scan_window
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.ble_scan_type = ble_scan_type
        self.ble_pairing = ble_pairing
        self.dev_state = dev_state
        self.gatt = gatt
        self.conn_interval = conn_interval
        self.service_class = service_class
        self.service_uid = service_uid
        self.char_path = char_path
        self.char_uid = char_uid
        self.data = data
        self.data_length = data_length
        self.data_duration = data_duration
        self.periodic_delay = periodic_delay
        self.ble_client_address = None
        self.write_handle = None
        self.ble_scan_filter_type = ble_scan_filter_type
        self.address = address
        self.service_uuid = service_uuid
        self.char_uuid = char_uuid
        self.characteristic = characteristic
        self.bond_info = bond_info

        if self.gatt:
            # Set up DUT for BLE advertising
            logger().info("start ble GATT service in DUT")
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
                set_smp=self.ble_pairing, bond_info=self.bond_info)
        else:
            # Set up DUT for BLE advertising
            logger().info("Initialising BLE")
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(
                set_smp=self.ble_pairing
            )
        assert (
                self.ble_dut_address is not None
        ), "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {self.ble_dut_address}")
        time.sleep(5)

    def add_whitelist(self):
        self.ble_client_address = self.ble_client.interfaces.bluetooth.get_ble_address()
        self.wifi_dut.interfaces.wifi.ble_set_scan_response_data()
        logger().info(" **** ADDING REMOTE DEVICE TO WHITELIST **** ")
        self.wifi_dut.interfaces.wifi.ble_add_white_list(self.ble_client_address)

    def add_service(self, service_uuid):
        logger().info(f"***** Configuring ble GATT service {hex(service_uuid)} in DUT *****")
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=hex(service_uuid))

    def connect_from_dut(self):
        self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                        ble_client_address=self.ble_client_address, mode="master", retries=3,
                                        ble_pairing=self.ble_pairing,
                                        dev_state=self.dev_state,
                                        max_conn_interval=self.conn_interval,
                                        min_conn_interval=self.conn_interval,
                                        timeout=30)

    def ble_disconnect(self, disconnect_from="remote"):

        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == self.dev_state, "DUT BLE device is not in connected state"

        if disconnect_from == "remote":
            logger().info(f"Initiating BLE disconnection from raspi")
            self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
        else:
            logger().info(f"Initiating BLE disconnection from DUT")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
        self.ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    def add_characteristic(self, characteristic_uuid):
        logger().info(f"***** Configuring ble GATT characteristic {hex(characteristic_uuid)} in DUT *****")
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=hex(characteristic_uuid))

    def ble_connect(self, role="master"):

        if role == "master":
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=self.ble_dut_address,
                service_classes=self.service_class
            )
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_client_address,
                                                             ble_scan_filter_type=self.ble_scan_filter_type, timeout=60,
                                                             )
            logger().info(f"Remote device found in scan results ,BLE scanning is successful")
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            self.wifi_dut.interfaces.wifi.ble_advertising = False
            self.connect_from_dut()

        else:
            logger().info("Starting DUT BLE advertising")
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            time.sleep(5)
            self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                ble_pairing=self.ble_pairing, services=self.service_class,
                dev_state=self.dev_state,
                max_conn_interval=self.conn_interval,
                min_conn_interval=self.conn_interval,
                timeout=30
            )
            async_events = self.wifi_dut.interfaces.wifi.get_async_events()
            logger().info(f"async_events:{async_events}")

    def advertise_remote_device(self):
        self.ble_client_address = self.sl_collections.advertise_remote_device(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
        )

    def advertise_dut(self):
        logger().info(f"Advertising the DUT")
        self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)

    def scan_and_connect_from_remote(self):
        self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            ble_pairing=self.ble_pairing,
            dev_state=self.dev_state,
            services=self.service_class,
            max_conn_interval=self.conn_interval,
            min_conn_interval=self.conn_interval,
            timeout=30
        )

    def scan_and_connect_from_dut(self):
        self.sl_collections.scan_and_connect_from_dut(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_client_address=self.ble_client_address,
            dev_state=self.dev_state,
            max_conn_interval=self.conn_interval,
            min_conn_interval=self.conn_interval
        )

    def check_scan_functionality_dut(self):
        self.ble_client_address = self.sl_collections.check_ble_scan_functionality(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_address=self.ble_dut_address,
            ble_scan_type=self.ble_scan_type,
            timeout=60,
            services=self.service_class
        )

    def check_adv_functionality_dut(self):
        self.ble_client_address = self.sl_collections.check_ble_advertise_functionality(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            timeout=20,
        )

    def configure_buffer_mode(self, mode=None, count=None):
        logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} ****************")
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address,
                                                                buffer_mode=mode,
                                                                buffer_count=count)
        logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} Success ****************")

    def service_discovery_on_remote(self):
        self.char_path = self.sl_collections.service_discovery_on_remote(self.ble_client,
                                                                         service_uid=self.service_uid,
                                                                         char_uid=self.char_uid)
        logger().info(f"self.char_path:{self.char_path}")

    def service_discovery_on_dut(self):

        self.write_handle = self.sl_collections.service_discovery_on_dut(ble_dut=self.wifi_dut,
                                                                         ble_client_address=self.ble_client_address,
                                                                         service_uuid=self.service_uuid,
                                                                         char_uuid=self.char_uuid,
                                                                         characteristic=self.characteristic)

    def ble_conn_disconnect(self, disconnect_from="remote"):
            time.sleep(10)
            self.ble_disconnect(disconnect_from=disconnect_from)
    def enable_notifications_from_dut(self):
        logger().info(f"****** enabling notifications on remote****************")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=self.char_path,
                                                                                     char_uid=self.char_uid)
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address,
                                                            buffer_mode=1, buffer_count=2)
        sw = Stopwatch()
        count = 0
        logger().info(f"Send notifications from DUT")
        while sw.elapsed_sec <= self.data_duration:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(self.ble_client_address, data=self.data,
                                                                  data_address=self.address)
            time.sleep(self.periodic_delay)
            count += 1
        time.sleep(10)
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        assert len(notifications) > 0, "received data is empty"
        logger().info(f"notifications received on remote :{notifications}")
        assert len(notifications) == count, "number of notifications received are not matching with sent"
        logger().info(f"length of notifications received on remote :{len(notifications)}")
        assert notifications[0] in self.data, "failed to fetch data"
        # assert notifications in self.data, "failed to fetch data"

        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)


    def gatt_write_without_resp(self, write_handle, data_length=None, data=None, write_count=1,
                                bt_mon_log_file_name=None, address=None):

        logger().info(f"*******Write Without Response Start****************")

        def write():
            bt_mon_log_file = bt_mon_log_file_name
            time.sleep(2)
            with BleLogs(start_collecting_logs=True,
                         bt_log_path=bt_mon_log_file):
                self.wifi_dut.interfaces.wifi.ble_set_att_cmd(ble_remote_dev_address=self.ble_client_address,
                                                             handle=write_handle, data_length=data_length, data=data,
                                                             data_address=address)
            time.sleep(2)
            flag = False
            logger().info(" ***** Validating Write Without Response Start *****")
            with open(bt_mon_log_file, "r") as file_p:
                lines = file_p.readlines()

            acl_data_flag = att_flag = handle_flag = False
            for line in lines:
                if "> ACL Data RX: Handle" in line:
                    acl_data_flag = True
                    continue
                if "ATT: Write Command" in line and acl_data_flag is True:
                    att_flag = True
                    continue
                if "Handle:" in line:
                    if f"0x{write_handle:04X}" in line and att_flag is True:
                        handle_flag = True
                    continue
                if "Data:" in line and acl_data_flag is True and att_flag is True and handle_flag is True:
                    data_match = re.search(r'Data:(.*)', line)
                    hex_string = data_match.group(1) if data_match else ""
                    byte_array = bytes.fromhex(hex_string)
                    text = byte_array.decode('unicode_escape')
                    logger().info(f"Actual data :{data}  Expected data:{text}")
                    try:
                        assert data in text, "Actual data is not found"
                    except:
                        assert data[:237] in text, "Actual data is not found"
                    flag = True
                    break

            assert flag, "data is not found"
            logger().info(" ***** Validating Write Without Response Success *****")

        for i in range(write_count):
                write()

        logger().info(f"*******Write Without Response End****************")

    def enable_notifications_remote(self):

        if self.write_handle:
            logger().info(f"Enabling notification on dut")
            self.wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                            handle=(self.write_handle + 1), enable_notify=1)

            tw = Stopwatch()
            Data_received_on_dut = []
            while tw.elapsed_sec < self.data_duration:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        if "rsi_ble_on_gatt_write_event_gatt" in event.event_data:
                            received_data = re.findall(r"att_value: (.*)", event.event_data)
                            Data_received_on_dut = received_data + Data_received_on_dut
                            # received_data = ord(received_data[0])
                            logger().info(f"received_data:{Data_received_on_dut}")
            assert len(Data_received_on_dut) > 0, "Notifications not received on DUT"
            self.wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                            handle=(self.write_handle + 1), enable_notify=0)

    def scan_from_remote_device(self):
        self.ble_client_address = self.sl_collections.scan_from_remote_device(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
        )

    def run(self):
        if self.ble_test_type == "advertise":
            self.check_adv_functionality_dut()

        if self.ble_test_type == "scan":
            self.check_scan_functionality_dut()

        if self.ble_test_type == "slave":
            self.ble_connect(role="slave")

        if self.ble_test_type == "master":
            self.ble_connect(role="master")

        if self.ble_test_type == "scan_from_remote_device":
            self.scan_from_remote_device()

        if self.ble_test_type == "connect_from_remote":
            self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                            ble_dut_address=self.ble_dut_address, mode="slave",
                                            retries=3, ble_pairing=self.ble_pairing, dev_state=self.dev_state,
                                            max_conn_interval=self.conn_interval,
                                            min_conn_interval=self.conn_interval,
                                            timeout=20)

        if self.ble_test_type == "scan_and_connect_from_dut":
            self.scan_and_connect_from_dut()

        if self.ble_test_type == "scan_and_connect_from_remote":
            self.scan_and_connect_from_remote()

        if self.ble_test_type == "notify_tx":
            self.enable_notifications_from_dut()

        if self.ble_test_type == "notify_rx":
            self.enable_notifications_remote()

        if self.ble_test_type == "connect_disconnect":
            self.ble_conn_disconnect(disconnect_from="remote")

        if self.ble_test_type == "connect_as_master_notify_rx":
            self.ble_connect(role="master")
            self.service_discovery_on_dut()
            self.enable_notifications_remote()

        if self.ble_test_type == "gatt_write_without_resp":
            self.gatt_write_without_resp(write_handle=self.write_handle, data_length=self.data_length, data=self.data)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                    | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork', "channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)

def test_sta_ble_sdk_sta_ble_slave_dle_notifications_wlan_csa_c778124(
                wifi_sniffer,
                wifi_access_point,
                wifi_dut, ble_client,
                request, utf_constants, sl_collections,
                wifi_client,
                sniffer_filter
        ):
            """
            Test BLE notifications with WLAN Channel Switch Announcement (CSA) in STA+BLE coexistence.

            Steps:
            1. Configure WiFi and BLE devices with custom GATT service and characteristic.
            2. Start WiFi and BLE threads for scan and notification transmission.
            3. Start sniffer capture and connect BLE devices.
            4. Perform service discovery and notification transmission.
            5. Query STA channel before and after AP CSA.
            6. Validate sniffer capture and BLE disconnection.
            7. Clean up resources and validate channel switch.

            Args:
                wifi_sniffer: Sniffer device object.
                wifi_access_point: WiFi AP device object.
                wifi_dut: Device under test (DUT) object.
                ble_client: BLE client device object.
                request: Pytest request object.
                utf_constants: Test constants.
                sl_collections: Shared library collections for test utilities.
                wifi_client: WiFi client device object.
                sniffer_filter: Sniffer filter configuration.

            Raises:
                AssertionError: If channel is not changed in STA after CSA or other test failures.
            """
            ble_dut_addr = ""
            ble_obj = None
            try:
                test_name = request.node.name
                ping_count = utf_constants.get("ping_count")
                test_type = "join"

                wifi_obj = WifiJoinThread(
                    wifi_sniffer=wifi_sniffer,
                    wifi_dut=wifi_dut,
                    wifi_access_point=wifi_access_point,
                    testcase=test_name,
                    wifi_client=wifi_client,
                    sl_collections=sl_collections,
                    ping_count=ping_count,
                    sniffer_filter=sniffer_filter,
                    test_type=test_type,
                    test_case_id="778124"
                )
                service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
                char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
                # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
                index = 1
                address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

                ble_obj = BleThread(
                    wifi_dut=wifi_dut,
                    ble_client=ble_client,
                    sl_collections=sl_collections,
                    ble_test_type="notify_tx",
                    dev_state=8,
                    char_path=None, char_uid=char_uid1, data=data,
                    service_uid=service_uid,
                    data_length=20, data_duration=120,
                    periodic_delay=0.5,
                    ble_pairing=1,
                    gatt=True,
                    address=address2,
                    conn_interval=45
                )

                # Create Custom services on DUT
                # Create Custom services, attributes, values
                logger().info("Creating new custom gatt service in DUT")
                ble_obj.add_service(service_uuid=0xAABB)
                logger().info("Adding custom characteristic declaration to the custom service")
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                               value_handler_num=index + 1)
                logger().info("Adding characteristic value attribute to the service")
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

                logger().info("configuring the Sniffer with the channel")
                wifi_sniffer.interfaces.capture.configure_interface(
                    channel=wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
                wifi_obj.start()
                ble_obj.ble_connect(role="slave")
                ble_obj.service_discovery_on_remote()
                ble_obj.start()
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA before CSA: {channel}, Band: {band}")
                """ Need to execute the WLAN AP CSA command to set the channel for AP """
                wifi_access_point.interfaces.wifi.enable_disable_csa(11, 20, 1)
                logger().info("Waiting for 30 seconds for CSA to complete")
                time.sleep(30)
                """ Need to add the code for STA Channel inquiry"""
                new_channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA after CSA: {new_channel}, Band: {band}")
                ble_obj.wait_for_exit()
                wifi_obj.wait_for_exit()
                time.sleep(2)
                wifi_sniffer.interfaces.capture.stop_capture()
                wifi_dut.interfaces.wifi.memory_free(address2)
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
                ble_obj.ble_disconnect()
                logger().info("sniffer validation is successful")
                assert new_channel is not 11, "Channel is not changed in STA after CSA"

            except Exception as Ex:
                sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
            finally:
                ble_client.interfaces.bluetooth.close()
                if ble_obj is not None:
                    ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                    sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                               ble_client_address=ble_obj.ble_client_address,
                                               ble_dut_address=ble_obj.ble_dut_address)




@pytest.mark.run
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                    | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA3', "passphrase": 'thisisatestnetwork', "channel": 11})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)

def test_sta_ble_sdk_sta_ble_central_ble_rx_notifications_with_csa_wpa3_security_c778125(
                wifi_sniffer,
                wifi_access_point,
                wifi_dut, ble_client,
                request, utf_constants, sl_collections,
                wifi_client,
                sniffer_filter
        ):
            ble_dut_addr = ""
            ble_obj = None
            try:
                test_name = request.node.name
                ping_count = utf_constants.get("ping_count")
                test_type = "join"

                wifi_obj = WifiJoinThread(
                    wifi_sniffer=wifi_sniffer,
                    wifi_dut=wifi_dut,
                    wifi_access_point=wifi_access_point,
                    testcase=test_name,
                    wifi_client=wifi_client,
                    sl_collections=sl_collections,
                    ping_count=ping_count,
                    sniffer_filter=sniffer_filter,
                    test_type=test_type,
                    test_case_id= "778125"
                )
                service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
                char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
                # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
                index = 1
                address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

                ble_obj = BleThread(
                    wifi_dut=wifi_dut,
                    ble_client=ble_client,
                    sl_collections=sl_collections,
                    ble_test_type="notify_rx",
                    dev_state=8,
                    char_path=None, char_uid=char_uid1, data=data,
                    service_uid=service_uid,
                    data_length=20, data_duration=120,
                    periodic_delay=0.5,
                    ble_pairing=1,
                    gatt=True,
                    address=address2,
                    conn_interval=45
                )

                # Create Custom services on DUT
                # Create Custom services, attributes, values
                logger().info("Creating new custom gatt service in DUT")
                ble_obj.add_service(service_uuid=0xAABB)
                logger().info("Adding custom characteristic declaration to the custom service")
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                               value_handler_num=index + 1)
                logger().info("Adding characteristic value attribute to the service")
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

                logger().info("configuring the Sniffer with the channel")
                wifi_sniffer.interfaces.capture.configure_interface(
                    channel=wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
                wifi_obj.start()
                ble_obj.ble_connect(role="master")
                ble_obj.service_discovery_on_remote()
                ble_obj.start()
                ble_obj.enable_notifications_remote()
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA before CSA: {channel}, Band: {band}")
                """ Need to execute the WLAN AP CSA command to set the channel for AP """
                wifi_access_point.interfaces.wifi.enable_disable_csa(4, 20, 1)
                logger().info("Waiting for 30 seconds for CSA to complete")
                time.sleep(30)
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA after CSA: {channel}, Band: {band}")
                ble_obj.wait_for_exit()
                wifi_obj.wait_for_exit()
                time.sleep(2)
                wifi_sniffer.interfaces.capture.stop_capture()
                wifi_dut.interfaces.wifi.memory_free(address2)
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
                ble_obj.ble_disconnect()
                logger().info("sniffer validation is successful")
                assert channel is not 4, "Channel is not changed in STA after CSA"

            except Exception as Ex:
                sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
            finally:
                ble_client.interfaces.bluetooth.close()
                if ble_obj is not None:
                    ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                    sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                               ble_client_address=ble_obj.ble_client_address,
                                               ble_dut_address=ble_obj.ble_dut_address)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                    | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork', "channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)

def test_sta_ble_with_csa_with_csa_count_1_ble_scan_with_si300ms_sw100ms_c778126(
                wifi_sniffer,
                wifi_access_point,
                wifi_dut, ble_client,
                request, utf_constants, sl_collections,
                wifi_client,
                sniffer_filter
        ):
            ble_dut_addr = ""
            ble_obj = None
            try:
                test_name = request.node.name
                ping_count = utf_constants.get("ping_count")
                test_type = "join"

                wifi_obj = WifiJoinThread(
                    wifi_sniffer=wifi_sniffer,
                    wifi_dut=wifi_dut,
                    wifi_access_point=wifi_access_point,
                    testcase=test_name,
                    wifi_client=wifi_client,
                    sl_collections=sl_collections,
                    ping_count=ping_count,
                    sniffer_filter=sniffer_filter,
                    test_type=test_type,
                    test_case_id="778126"
                )
                service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
                char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
                # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
                index = 1
                address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

                ble_obj = BleThread(
                    wifi_dut=wifi_dut,
                    ble_client=ble_client,
                    sl_collections=sl_collections,
                    ble_test_type="scan",
                    ble_scan_interval=300,
                    ble_scan_window=100,
                )

                # Create Custom services on DUT
                # Create Custom services, attributes, values
                logger().info("Creating new custom gatt service in DUT")
                ble_obj.add_service(service_uuid=0xAABB)
                logger().info("Adding custom characteristic declaration to the custom service")
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                               value_handler_num=index + 1)
                logger().info("Adding characteristic value attribute to the service")
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

                logger().info("configuring the Sniffer with the channel")
                wifi_sniffer.interfaces.capture.configure_interface(
                    channel=wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
                wifi_obj.start()
                ble_obj.start()
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA before CSA: {channel}, Band: {band}")
                """ Need to execute the WLAN AP CSA command to set the channel for AP """
                wifi_access_point.interfaces.wifi.enable_disable_csa(11, 1, 1)
                logger().info("Waiting for 30 seconds for CSA to complete")
                time.sleep(30)
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA after CScA: {channel}, Band: {band}")
                ble_obj.wait_for_exit()
                wifi_obj.wait_for_exit()
                time.sleep(2)
                wifi_sniffer.interfaces.capture.stop_capture()
                wifi_dut.interfaces.wifi.memory_free(address2)
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
                logger().info("sniffer validation is successful")
                assert channel is not 11, "Channel is not changed in STA after CSA"

            except Exception as Ex:
                sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
            finally:
                ble_client.interfaces.bluetooth.close()
                if ble_obj is not None:
                    ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                    sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                               ble_client_address=ble_obj.ble_client_address,
                                               ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                    | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork', "channel": 11})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)

def test_sta_ble_csa_beacon_count_254_with_ble_connection_with_ci45ms_C778127(
                wifi_sniffer,
                wifi_access_point,
                wifi_dut, ble_client,
                request, utf_constants, sl_collections,
                wifi_client,
                sniffer_filter
        ):
            ble_dut_addr = ""
            ble_obj = None
            try:
                test_name = request.node.name
                ping_count = utf_constants.get("ping_count")
                test_type = "join"

                wifi_obj = WifiJoinThread(
                    wifi_sniffer=wifi_sniffer,
                    wifi_dut=wifi_dut,
                    wifi_access_point=wifi_access_point,
                    testcase=test_name,
                    wifi_client=wifi_client,
                    sl_collections=sl_collections,
                    ping_count=ping_count,
                    sniffer_filter=sniffer_filter,
                    test_type=test_type,
                    test_case_id="778127"
                )
                service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
                char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
                # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
                index = 1
                address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

                ble_obj = BleThread(
                    wifi_dut=wifi_dut,
                    ble_client=ble_client,
                    sl_collections=sl_collections,
                    ble_test_type="notify_tx",
                    dev_state=8,
                    char_path=None, char_uid=char_uid1, data=data,
                    service_uid=service_uid,
                    data_length=20, data_duration=120,
                    periodic_delay=0.5,
                    ble_pairing=1,
                    gatt=True,
                    address=address2,
                    conn_interval=45
                )

                # Create Custom services on DUT
                # Create Custom services, attributes, values
                logger().info("Creating new custom gatt service in DUT")
                ble_obj.add_service(service_uuid=0xAABB)
                logger().info("Adding custom characteristic declaration to the custom service")
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                               value_handler_num=index + 1)
                logger().info("Adding characteristic value attribute to the service")
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

                logger().info("configuring the Sniffer with the channel")
                wifi_sniffer.interfaces.capture.configure_interface(
                    channel=wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
                wifi_obj.start()
                ble_obj.ble_connect(role="master")
                ble_obj.service_discovery_on_remote()
                ble_obj.start()
                ble_obj.enable_notifications_remote()
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA before CSA: {channel}, Band: {band}")
                """ Need to execute the WLAN AP CSA command to set the channel for AP """
                wifi_access_point.interfaces.wifi.enable_disable_csa(4, 254, 1)
                logger().info("Waiting for 60 seconds for CSA to complete")
                time.sleep(60)
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA after CSA: {channel}, Band: {band}")
                ble_obj.wait_for_exit()
                wifi_obj.wait_for_exit()
                time.sleep(2)
                wifi_sniffer.interfaces.capture.stop_capture()
                wifi_dut.interfaces.wifi.memory_free(address2)
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
                ble_obj.ble_disconnect()
                logger().info("sniffer validation is successful")
                assert channel is not 4, "Channel is not changed in STA after CSA"

            except Exception as Ex:
                sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
            finally:
                ble_client.interfaces.bluetooth.close()
                if ble_obj is not None:
                    ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                    sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                               ble_client_address=ble_obj.ble_client_address,
                                               ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.run
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                    | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2Enterprise', "passphrase": '12345678', "channel": 8,
                          "protected_management_frame" : "Required"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)

def test_sta_ble_sdk_with_csa_unsupported_channel_wpa3_enterprise_security_c778128(
                wifi_sniffer,
                wifi_access_point,
                wifi_dut, ble_client,
                request, utf_constants, sl_collections,
                wifi_client,
                sniffer_filter,
                radius_server
        ):
            ble_dut_addr = ""
            ble_obj = None
            try:
                logger().info(
                    f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                    f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
                test_name = request.node.name
                ping_count = utf_constants.get("ping_count")
                test_type = "join"

                wifi_obj = WifiJoinThread(
                    wifi_sniffer=wifi_sniffer,
                    wifi_dut=wifi_dut,
                    wifi_access_point=wifi_access_point,
                    testcase=test_name,
                    wifi_client=wifi_client,
                    sl_collections=sl_collections,
                    ping_count=ping_count,
                    sniffer_filter=sniffer_filter,
                    test_type=test_type,
                    test_case_id="778128",
                    eap_type="peap",
                )
                service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
                char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
                #####data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data //already commeneted
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
                index = 1
                address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

                ble_obj = BleThread(
                    wifi_dut=wifi_dut,
                    ble_client=ble_client,
                    sl_collections=sl_collections,
                    ble_test_type="notify_rx",
                    dev_state=8,
                    char_path=None, char_uid=char_uid1, data=data,
                    service_uid=service_uid,
                    data_length=20, data_duration=120,
                    periodic_delay=0.5,
                    ble_pairing=1,
                    gatt=True,
                    address=address2,
                    conn_interval=45
                )

                # Create Custom services on DUT
                # Create Custom services, attributes, values

                logger().info("Creating new custom gatt service in DUT")
                ble_obj.add_service(service_uuid=0xAABB)
                logger().info("Adding custom characteristic declaration to the custom service")
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                               value_handler_num=index + 1)
                logger().info("Adding characteristic value attribute to the service")
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

                # wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
                #
                # wifi_access_point.interfaces.wifi.start_ap()
                logger().info("configuring the Sniffer with the channel")
                wifi_sniffer.interfaces.capture.configure_interface(
                    channel=wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
                wifi_dut.interfaces.wifi.set_eap_credentials()

                wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
                wifi_access_point.interfaces.wifi.start_ap()
                wifi_obj.start()
                time.sleep(30)
                ble_obj.ble_connect(role="master")
                ble_obj.service_discovery_on_remote()
                ble_obj.start()
                ble_obj.enable_notifications_remote()
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA before CSA: {channel}, Band: {band}")
                """ Need to execute the WLAN AP CSA command to set the channel for AP """
                ap_new_csa_channel = 15
                wifi_access_point.interfaces.wifi.enable_disable_csa(ap_new_csa_channel, 255, 1)
                logger().info("Waiting for 30 seconds for CSA to complete")
                time.sleep(30)
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA after CSA: {channel}, Band: {band}")
                ble_obj.wait_for_exit()
                wifi_obj.wait_for_exit()
                time.sleep(2)
                wifi_sniffer.interfaces.capture.stop_capture()
                wifi_dut.interfaces.wifi.memory_free(address2)
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
                ble_obj.ble_disconnect()
                logger().info("sniffer validation is successful")
                logger().info(f"AP CSA channel: {ap_new_csa_channel}, STA channel after CSA: {channel}")
                assert channel is not ap_new_csa_channel, "Channel is not changed in STA after CSA"

            except Exception as Ex:
                sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
            finally:
                ble_client.interfaces.bluetooth.close()
                if ble_obj is not None:
                    ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                    sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                               ble_client_address=ble_obj.ble_client_address,
                                               ble_dut_address=ble_obj.ble_dut_address)


# @pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                    | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                                | Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               |  Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)

def test_sta_ble_csa_with_ota_firmware_update_with_ble_conn_CI_30ms_C778129(
                http_server,
                wifi_sniffer,
                wifi_access_point,
                wifi_dut, ble_client,
                request, utf_constants, sl_collections,
                wifi_client,
                sniffer_filter,

        ):
            ble_dut_addr = ""
            ble_obj = None
            try:
                test_name = request.node.name
                ping_count = utf_constants.get("ping_count")
                test_type = "join"

                wifi_obj = WifiJoinThread(
                    wifi_sniffer=wifi_sniffer,
                    wifi_dut=wifi_dut,
                    wifi_access_point=wifi_access_point,
                    testcase=test_name,
                    wifi_client=wifi_client,
                    sl_collections=sl_collections,
                    ping_count=ping_count,
                    sniffer_filter=sniffer_filter,
                    test_type=test_type,
                    test_case_id= "778129",
                    http_server=http_server
                )
                service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
                char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
                data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
                index = 1
                address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

                ble_obj = BleThread(
                    wifi_dut=wifi_dut,
                    ble_client=ble_client,
                    sl_collections=sl_collections,
                    ble_test_type="scan_and_connect_from_dut",
                    dev_state=8,
                    char_path=None, char_uid=char_uid1, data=data,
                    service_uid=service_uid,
                    data_length=20, data_duration=120,
                    periodic_delay=0.5,
                    ble_pairing=1,
                    gatt=True,
                    address=address2,
                    conn_interval=45
                )

                # Create Custom services on DUT
                # Create Custom services, attributes, values
                logger().info("Creating new custom gatt service in DUT")
                ble_obj.add_service(service_uuid=0xAABB)
                logger().info("Adding custom characteristic declaration to the custom service")
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                               value_handler_num=index + 1)
                logger().info("Adding characteristic value attribute to the service")
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)
                ble_obj.ble_connect(role="master")
                ble_obj.service_discovery_on_remote()
                ble_obj.start()
                ble_obj.enable_notifications_remote()
                wifi_obj.start()
                logger().info("Waiting for 10 seconds after wlan object start")
                time.sleep(10)

                # channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                # logger().info(f"Channel in STA before CSA: {channel}, Band: {band}")
                channel = 11
                wifi_access_point.interfaces.wifi.enable_disable_csa(11, 255, 0)
                logger().info("configuring the Sniffer with the channel")
                wifi_sniffer.interfaces.capture.configure_interface(
                    channel=11
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
                logger().info("Waiting for 30 seconds for CSA to complete")
                time.sleep(30)
                """ Need to add the code for STA Channel inquiry"""
                # channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                # logger().info(f"Channel in STA after CSA: {channel}, Band: {band}")
                ble_obj.wait_for_exit()
                wifi_obj.wait_for_exit()
                time.sleep(2)
                wifi_sniffer.interfaces.capture.stop_capture()
                wifi_dut.interfaces.wifi.memory_free(address2)
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
                ble_obj.ble_disconnect()
                wifi_obj.sniffer_validation_scan()
                logger().info("sniffer validation is successful")
                assert channel is not 11, "Channel is not changed in STA after CSA"

            except Exception as Ex:
                sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
            finally:
                ble_client.interfaces.bluetooth.close()
                if ble_obj is not None:
                    ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                    sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                               ble_client_address=ble_obj.ble_client_address,
                                               ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                    | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                                 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)

def test_sta_ble_csa_with_aws_mqtt_publish_with_ble_conn_C778130(
                wifi_sniffer,
                wifi_access_point,
                wifi_dut, ble_client,
                request, utf_constants, sl_collections,
                wifi_client,
                sniffer_filter,
                aws_iot_client
        ):
            ble_dut_addr = ""
            ble_obj = None
            try:
                test_name = request.node.name
                ping_count = utf_constants.get("ping_count")
                test_type = "join"

                wifi_obj = WifiJoinThread(
                    wifi_sniffer=wifi_sniffer,
                    wifi_dut=wifi_dut,
                    wifi_access_point=wifi_access_point,
                    testcase=test_name,
                    wifi_client=wifi_client,
                    sl_collections=sl_collections,
                    ping_count=ping_count,
                    sniffer_filter=sniffer_filter,
                    test_type=test_type,
                    test_case_id= "778130",
                    aws_iot_client=aws_iot_client
                )
                service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
                char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
                # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
                index = 1
                address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

                ble_obj = BleThread(
                    wifi_dut=wifi_dut,
                    ble_client=ble_client,
                    sl_collections=sl_collections,
                    ble_test_type="connect_from_remote",
                    dev_state=8,
                    char_path=None, char_uid=char_uid1, data=data,
                    service_uid=service_uid,
                    data_length=20, data_duration=120,
                    periodic_delay=0.5,
                    ble_pairing=1,
                    gatt=True,
                    address=address2,
                    conn_interval=45
                )

                # Create Custom services on DUT
                # Create Custom services, attributes, values
                logger().info("Creating new custom gatt service in DUT")
                ble_obj.add_service(service_uuid=0xAABB)
                logger().info("Adding custom characteristic declaration to the custom service")
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                               value_handler_num=index + 1)
                logger().info("Adding characteristic value attribute to the service")
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

                logger().info("configuring the Sniffer with the channel")
                wifi_sniffer.interfaces.capture.configure_interface(
                    channel=wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
                wifi_obj.start()
                ble_obj.ble_connect(role="master")
                ble_obj.service_discovery_on_remote()
                ble_obj.start()
                ble_obj.enable_notifications_remote()
                """ Need to add the code for AWS MQTT publish """
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA before CSA: {channel}, Band: {band}")
                """ Need to execute the WLAN AP CSA command to set the channel for AP """
                wifi_access_point.interfaces.wifi.enable_disable_csa(11, 255, 1)
                logger().info("Waiting for 30 seconds for CSA to complete")
                time.sleep(30)
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA after CSA: {channel}, Band: {band}")
                ble_obj.wait_for_exit()
                wifi_obj.wait_for_exit()
                time.sleep(2)
                wifi_sniffer.interfaces.capture.stop_capture()
                wifi_dut.interfaces.wifi.memory_free(address2)
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
                ble_obj.ble_disconnect()
                wifi_obj.sniffer_validation_scan()
                logger().info("sniffer validation is successful")
                assert channel is not 11, "Channel is not changed in STA after CSA"

            except Exception as Ex:
                sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
            finally:
                ble_client.interfaces.bluetooth.close()
                if ble_obj is not None:
                    ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                    sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                               ble_client_address=ble_obj.ble_client_address,
                                               ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                    | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)

def test_sta_ble_sdk_sta_ble_master_dle_notifications_with_2ble_wlan_csa_C778131(
                wifi_sniffer,
                wifi_access_point,
                wifi_dut, ble_client,
                request, utf_constants, sl_collections,
                wifi_client,
                sniffer_filter
        ):
            ble_dut_addr = ""
            ble_obj = None
            try:
                test_name = request.node.name
                ping_count = utf_constants.get("ping_count")
                test_type = "join"

                wifi_obj = WifiJoinThread(
                    wifi_sniffer=wifi_sniffer,
                    wifi_dut=wifi_dut,
                    wifi_access_point=wifi_access_point,
                    testcase=test_name,
                    wifi_client=wifi_client,
                    sl_collections=sl_collections,
                    ping_count=ping_count,
                    sniffer_filter=sniffer_filter,
                    test_type=test_type,
                )
                service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
                char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
                # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
                index = 1
                address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

                ble_obj = BleThread(
                    wifi_dut=wifi_dut,
                    ble_client=ble_client,
                    sl_collections=sl_collections,
                    ble_test_type="notify_tx",
                    dev_state=8,
                    char_path=None, char_uid=char_uid1, data=data,
                    service_uid=service_uid,
                    data_length=20, data_duration=120,
                    periodic_delay=0.5,
                    ble_pairing=1,
                    gatt=True,
                    address=address2,
                    conn_interval=45
                )

                # Create Custom services on DUT
                # Create Custom services, attributes, values
                logger().info("Creating new custom gatt service in DUT")
                ble_obj.add_service(service_uuid=0xAABB)
                logger().info("Adding custom characteristic declaration to the custom service")
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                               value_handler_num=index + 1)
                logger().info("Adding characteristic value attribute to the service")
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

                logger().info("configuring the Sniffer with the channel")
                wifi_sniffer.interfaces.capture.configure_interface(
                    channel=wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
                wifi_obj.start()
                ble_obj.ble_connect(role="slave")
                ble_obj.service_discovery_on_remote()
                ble_obj.start()
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA before CSA: {channel}, Band: {band}")
                """ Need to execute the WLAN AP CSA command to set the channel for AP """
                for i in range(0, 20):
                    wifi_access_point.interfaces.wifi.enable_disable_csa(11, 20, 1)
                logger().info("Waiting for 30 seconds for CSA to complete")
                time.sleep(30)
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA after CSA: {channel}, Band: {band}")
                ble_obj.wait_for_exit()
                wifi_obj.wait_for_exit()
                time.sleep(2)
                wifi_sniffer.interfaces.capture.stop_capture()
                wifi_dut.interfaces.wifi.memory_free(address2)
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
                ble_obj.ble_disconnect()
                wifi_obj.sniffer_validation_scan()
                logger().info("sniffer validation is successful")
                assert channel is not 11, "Channel is not changed in STA after CSA"

            except Exception as Ex:
                sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
            finally:
                ble_client.interfaces.bluetooth.close()
                if ble_obj is not None:
                    ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                    sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                               ble_client_address=ble_obj.ble_client_address,
                                               ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.run
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                    | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)

def test_sta_ble_sdk_ble_central_conn_disconnection_with_csa_C778132(
                wifi_sniffer,
                wifi_access_point,
                wifi_dut, ble_client,
                request, utf_constants, sl_collections,
                wifi_client,
                sniffer_filter
        ):
            ble_dut_addr = ""
            ble_obj = None
            try:
                test_name = request.node.name
                ping_count = utf_constants.get("ping_count")
                test_type = "join"

                wifi_obj = WifiJoinThread(
                    wifi_sniffer=wifi_sniffer,
                    wifi_dut=wifi_dut,
                    wifi_access_point=wifi_access_point,
                    testcase=test_name,
                    wifi_client=wifi_client,
                    sl_collections=sl_collections,
                    ping_count=ping_count,
                    sniffer_filter=sniffer_filter,
                    test_type=test_type,
                    test_case_id="778132"
                )
                service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
                char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
                # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
                index = 1
                address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

                ble_obj = BleThread(
                    wifi_dut=wifi_dut,
                    ble_client=ble_client,
                    sl_collections=sl_collections,
                    ble_test_type="connect_disconnect",
                    dev_state=8,
                    char_path=None, char_uid=char_uid1, data=data,
                    service_uid=service_uid,
                    data_length=20, data_duration=120,
                    periodic_delay=0.5,
                    ble_pairing=1,
                    gatt=True,
                    address=address2,
                    conn_interval=45
                )

                # Create Custom services on DUT
                # Create Custom services, attributes, values
                logger().info("Creating new custom gatt service in DUT")
                ble_obj.add_service(service_uuid=0xAABB)
                logger().info("Adding custom characteristic declaration to the custom service")
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                               value_handler_num=index + 1)
                logger().info("Adding characteristic value attribute to the service")
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

                logger().info("configuring the Sniffer with the channel")
                wifi_sniffer.interfaces.capture.configure_interface(
                    channel=wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
                wifi_obj.start()
                ble_obj.ble_connect(role="master")
                ble_obj.service_discovery_on_remote()
                ble_obj.start()
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA before CSA: {channel}, Band: {band}")
                time.sleep(10);
                wifi_obj.wait_for_exit()
                for i in range(0, 2):
                    new_channel = random.randint(1,11)
                    logger().info(f"Changing AP channel to {new_channel} for CSA")
                    wifi_access_point.interfaces.wifi.enable_disable_csa(new_channel, 20, 1)
                    logger().info("Waiting for 20 seconds for CSA to complete")
                    time.sleep(20)
                    sta_channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                    logger().info(f"Channel in STA after CSA: {sta_channel}, Band: {band}")
                    assert sta_channel != new_channel, f"Channel is not changed in STA after CSA. Expected: {new_channel}, Got: {sta_channel}"
                ble_obj.wait_for_exit()
                time.sleep(2)
                wifi_sniffer.interfaces.capture.stop_capture()
                wifi_dut.interfaces.wifi.memory_free(address2)
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
            except Exception as Ex:
                sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
            finally:
                ble_client.interfaces.bluetooth.close()
                if ble_obj is not None:
                    ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                    sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                               ble_client_address=ble_obj.ble_client_address,
                                               ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.run
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                    | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)

def test_sta_ble_sdk_ble_peripheral_conn_disconnection_with_csa_C778133(
                wifi_sniffer,
                wifi_access_point,
                wifi_dut, ble_client,
                request, utf_constants, sl_collections,
                wifi_client,
                sniffer_filter
        ):
            ble_dut_addr = ""
            ble_obj = None
            try:
                test_name = request.node.name
                ping_count = utf_constants.get("ping_count")
                test_type = "join"

                wifi_obj = WifiJoinThread(
                    wifi_sniffer=wifi_sniffer,
                    wifi_dut=wifi_dut,
                    wifi_access_point=wifi_access_point,
                    testcase=test_name,
                    wifi_client=wifi_client,
                    sl_collections=sl_collections,
                    ping_count=ping_count,
                    sniffer_filter=sniffer_filter,
                    test_type=test_type,
                    test_case_id="778133"
                )
                service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
                char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
                # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
                index = 1
                address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

                ble_obj = BleThread(
                    wifi_dut=wifi_dut,
                    ble_client=ble_client,
                    sl_collections=sl_collections,
                    ble_test_type="connect_disconnect",
                    dev_state=8,
                    char_path=None, char_uid=char_uid1, data=data,
                    service_uid=service_uid,
                    data_length=20, data_duration=120,
                    periodic_delay=0.5,
                    ble_pairing=1,
                    gatt=True,
                    address=address2,
                    conn_interval=45
                )

                # Create Custom services on DUT
                # Create Custom services, attributes, values
                logger().info("Creating new custom gatt service in DUT")
                ble_obj.add_service(service_uuid=0xAABB)
                logger().info("Adding custom characteristic declaration to the custom service")
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                               value_handler_num=index + 1)
                logger().info("Adding characteristic value attribute to the service")
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

                logger().info("configuring the Sniffer with the channel")
                wifi_sniffer.interfaces.capture.configure_interface(
                    channel=wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
                wifi_obj.start()
                ble_obj.ble_connect(role="slave")
                ble_obj.service_discovery_on_remote()
                ble_obj.start()
                """ Need to add the code for STA Channel inquiry"""
                channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                logger().info(f"Channel in STA before CSA: {channel}, Band: {band}")
                wifi_obj.wait_for_exit()
                """ Need to execute the WLAN AP CSA command to set the channel for AP """
                for i in range(0, 5):
                    new_channel = random.randint(1,11)
                    logger().info(f"Changing AP channel to {new_channel} for CSA")
                    wifi_access_point.interfaces.wifi.enable_disable_csa(new_channel, 20, 1)
                    logger().info("Waiting for 20 seconds for CSA to complete")
                    time.sleep(20)
                    sta_channel, band = wifi_dut.interfaces.wifi.get_channel_info(interface="client")
                    logger().info(f"Channel in STA after CSA: {sta_channel}, Band: {band}")
                    assert sta_channel != new_channel, f"Channel is not changed in STA after CSA. Expected: {new_channel}, Got: {sta_channel}"
                ble_obj.wait_for_exit()
                time.sleep(2)
                wifi_sniffer.interfaces.capture.stop_capture()
                wifi_dut.interfaces.wifi.memory_free(address2)
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
                logger().info("sniffer validation is successful")

            except Exception as Ex:
                sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
            finally:
                ble_client.interfaces.bluetooth.close()
                if ble_obj is not None:
                    ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                    sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                               ble_client_address=ble_obj.ble_client_address,
                                               ble_dut_address=ble_obj.ble_dut_address)

