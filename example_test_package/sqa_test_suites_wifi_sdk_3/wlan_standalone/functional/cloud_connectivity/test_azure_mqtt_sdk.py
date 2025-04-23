import re
import time
import pytest
import string
import random
from retry import retry
from threading import Thread
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xModuleType,
    Si91xBTFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap, Si91xCertificateType, Si91xCertIdentifier,
)
from utf.utf_config import UtfConfig
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.stopwatch import Stopwatch

def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. AZURE IOT HUB Account

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and get ip through DHCP
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from/to the dut address
        5. Create the socket and connect to the azure iot hub
        6. Subscribe to the topic, send the message and receive the message


    Author: Swathi.Chinthala

"""

def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

class Azure_iot_Thread():
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, ping_count=None, test_case=None,
                 sl_collections=None, sniffer_filter=None, power_save=None, ap_mac_address=None, azure_iot_clients=None,
                 wifi_client=None, test_type=None, disconnect=True, device_id="symmetric_device"):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ping_count = ping_count
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.sniffer_filter = sniffer_filter
        self.azure_iot_clients = azure_iot_clients
        self.wifi_client = wifi_client
        self.dut_addr = None
        self.power_save = power_save
        self.ap_mac_address = ap_mac_address
        self.connection_string = None
        self.test_type = test_type
        self.disconnect = disconnect
        self.device_id = device_id
        self.sock_id = None
        self.host_ip = None
        self.socket, self.init, self.subscribe = False, False, False
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")
        self.connection_string = self.azure_iot_clients.interfaces.device.config["connection_string_device"]
        [(self.host_name, self.device, self.shared_key)] = re.findall(
            r'HostName=(.*);DeviceId=(.*);SharedAccessKey=(.*)',
            self.connection_string)
    def subscribe_from_dut(self, timeout=120):
        self.wifi_dut.interfaces.wifi.azure_iot_subscribe(timeout=timeout)
        self.subscribe = True
        time.sleep(3)

    @retry(Exception, delay=5, tries=1)
    def azure_iot_init(self, timeout=120):
        if self.device_id == "x509_device":
            self.device_id = "x.509_self_signed_sha1"
            mode = 1
            self.shared_key = None
        else:
            mode = 0
        self.wifi_dut.interfaces.wifi.azure_iot_init(
            hostname=self.host_name,
            device_id=self.device_id,
            port=4002,
            mode=mode,
            symmetrickey=self.shared_key,
            timeout=timeout)
        self.init = True
        logger().info("azure iot init successful")

    def send_msg_from_device(self, message="Sending_d2c_message", count=3, duration=60):

        self.azure_iot_clients.interfaces.hub.received_messages.clear()

        with self.azure_iot_clients.interfaces.hub.start_receiving_events(duration=10):
            self.publish_from_dut(count=count, message=message, timeout=duration)
            time.sleep(5)
        assert message in self.azure_iot_clients.interfaces.hub.received_messages,\
            "message sent from device not received on cloud"
        logger().info(f"message sent from device received on cloud {message}")
        received_msgs = self.azure_iot_clients.interfaces.hub.received_messages

        assert received_msgs.count(message) == count,\
            "Number of times message sent from device not received on cloud"
        logger().info(f"Number of times message sent from device {count} received on cloud"
                      f" {received_msgs.count(message)}")

    def join_to_ap(self):
        if self.device_id == "symmetric_device":
            self.wifi_dut.interfaces.wifi.clear_certificate(cert_index=0,
                                                            cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                            cert_identifier=Si91xCertIdentifier.
                                                            SL_NET_TLS_CLIENT_CREDENTIAL_START)
            self.wifi_dut.interfaces.wifi.clear_certificate(cert_index=0,
                                                            cert_type=Si91xCertificateType.SL_NET_PRIVATE_KEY,
                                                            cert_identifier=Si91xCertIdentifier.
                                                            SL_NET_TLS_CLIENT_CREDENTIAL_START)

        # self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

        logger().info("connecting to access point.....")
        self.dut_addr = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            retry_count=3,
            associated=self.wifi_dut.interfaces.wifi.associated,
            power_save=self.power_save,
        )
        self.dut_addr['ap_mac_address'] = self.wifi_access_point.interfaces.wifi.bssid

        result = self.wifi_dut.interfaces.wifi.dns_get(domain_name=self.host_name,
                                                       query_timeout=20000,
                                                       timeout=100)
        self.host_ip = (result.decode()).strip()

    @retry(Exception, delay=5, tries=2)
    def publish_from_dut(self, count=1, message="hello", timeout=120):
        self.wifi_dut.interfaces.wifi.azure_iot_publish(payload=message,
                                                        maxcount=count, timeout=timeout)
    def connect_socket(self):

        self.sock_id = self.wifi_dut.interfaces.wifi.socket("AF_INET", "SOCK_STREAM", "IPPROTO_TCP")
        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(self.sock_id, "SOL_TCP", "TCP_ULP", "tls")
        self.wifi_dut.interfaces.wifi.bsdSetSocketOption(socket_fd=self.sock_id, option_level='SOL_SOCKET',
                                                         option_name='SO_RCVTIMEO')
        self.wifi_dut.interfaces.wifi.bsdSocketConnect(self.sock_id, self.host_ip, 4, 8883)  # "40.78.196.98")
        self.socket = True
        time.sleep(5)

    def azure_iot_disconnect(self):
        if self.subscribe:
            self.wifi_dut.interfaces.wifi.azure_iot_unsubscribe()
            self.subscribe = False
        if self.init:
            self.wifi_dut.interfaces.wifi.azure_iot_disconnect()
            self.init = False
        if self.socket:
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock_id)
            self.socket = False
        self.azure_iot_clients.interfaces.device.disconnect()
        time.sleep(2)

class Azure_Thread():
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, ping_count=None, test_case=None,
                 sl_collections=None, sniffer_filter=None, power_save=None, ap_mac_address=None, azure_iot_client=None,
                 wifi_client=None, test_type=None, disconnect=True, device_id="symmetric_device"):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ping_count = ping_count
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.sniffer_filter = sniffer_filter
        self.azure_iot_client = azure_iot_client
        self.wifi_client = wifi_client
        self.dut_addr = None
        self.power_save = power_save
        self.ap_mac_address = ap_mac_address
        self.connection_string = None
        self.test_type = test_type
        self.disconnect = disconnect
        self.device_id = device_id
        self.sock_id = None
        self.host_ip = None
        self.socket, self.init, self.subscribe = False, False, False
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")
        self.connection_string = self.azure_iot_client.interfaces.device.config["connection_string_device"]
        [(self.host_name, self.device, self.shared_key)] = re.findall(
            r'HostName=(.*);DeviceId=(.*);SharedAccessKey=(.*)',
            self.connection_string)

    @retry(Exception, delay=5, tries=2)
    def subscribe_from_dut(self, timeout=120):
        self.wifi_dut.interfaces.wifi.azure_iot_subscribe(timeout=timeout)
        self.subscribe = True
        time.sleep(3)

    @retry(Exception, delay=5, tries=2)
    def publish_from_dut(self, count=1, message="hello", timeout=120):
        self.wifi_dut.interfaces.wifi.azure_iot_publish(payload=message,
                                                        maxcount=count, timeout=timeout)

    def receive_messages_from_dut(self, retries=2, wait_time=3):

        for retry_count in range(retries):
            try:
                time.sleep(wait_time)
                recv_msg = self.wifi_dut.interfaces.wifi.azure_iot_recv(maxcount=1, maxtry=1, timeout=120)
                assert len(recv_msg), "Failed to receive published message in DUT"
                return recv_msg[-1]
            except Exception as err:
                logger().warning(f"Failed to receive published message in DUT\n{err}")
                if "0x1" in str(err):
                    self.wifi_dut.interfaces.wifi.is_dut_bad_state = True
                if "0x7" in str(err):
                    self.wifi_dut.interfaces.wifi.is_dut_bad_state = True
                if retry_count == retries - 1:
                    raise
                time.sleep(5)

    @retry(Exception, delay=5, tries=1)
    def azure_iot_init(self, timeout=120):
        if self.device_id == "x509_device":
            self.device_id = "x.509_self_signed_sha1"
            mode = 1
            self.shared_key=None
        else:
            mode = 0
        self.wifi_dut.interfaces.wifi.azure_iot_init(
            hostname=self.host_name,
            device_id=self.device_id,
            port=4002,
            mode=mode,
            symmetrickey=self.shared_key,
            timeout=timeout)
        self.init = True
        logger().info("azure iot init successful")
        # time.sleep(5)

    def send_msg_from_cloud(self, message="Sending_c2d_message", count=3, maxtry=10, duration=120):

        for i in range(count):
            logger().info(f"Sending message from cloud to device :{message}")
            self.azure_iot_client.interfaces.hub.send_message_to_device(
                self.device_id, message  # "{message} {count}"
            )
            recv_msg = self.receive_messages_from_dut()
            assert message == recv_msg, "Failed to receive published message in DUT"
            time.sleep(2)

    def send_msg_from_device(self, message="Sending_d2c_message", count=3, duration=60):

        self.azure_iot_client.interfaces.hub.received_messages.clear()

        with self.azure_iot_client.interfaces.hub.start_receiving_events(duration=10):
            self.publish_from_dut(count=count, message=message, timeout=duration)
            time.sleep(5)
        assert message in self.azure_iot_client.interfaces.hub.received_messages,\
            "message sent from device not received on cloud"
        logger().info(f"message sent from device received on cloud {message}")
        received_msgs = self.azure_iot_client.interfaces.hub.received_messages

        assert received_msgs.count(message) == count,\
            "Number of times message sent from device not received on cloud"
        logger().info(f"Number of times message sent from device {count} received on cloud"
                      f" {received_msgs.count(message)}")


    def connect_socket(self):

        self.sock_id = self.wifi_dut.interfaces.wifi.socket("AF_INET", "SOCK_STREAM", "IPPROTO_TCP")
        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(self.sock_id, "SOL_TCP", "TCP_ULP", "tls")
        self.wifi_dut.interfaces.wifi.bsdSetSocketOption(socket_fd=self.sock_id, option_level='SOL_SOCKET',
                                                         option_name='SO_RCVTIMEO')
        self.wifi_dut.interfaces.wifi.bsdSocketConnect(self.sock_id, self.host_ip, 4, 8883)  # "40.78.196.98")
        self.socket = True
        time.sleep(5)

    def azure_iot_connect(self, retries=3):
        status = False
        for retry_count in range(retries):
            try:
                self.connect_socket()
                self.azure_iot_init()
                status=True
                break
            except:
                logger().info("retrying to connect to azure iot")
                self.azure_iot_disconnect()
        assert status, "Failed to connect to azure iot"



    def azure_iot_disconnect(self):
        if self.subscribe:
            self.wifi_dut.interfaces.wifi.azure_iot_unsubscribe()
            self.subscribe = False
        if self.init:
            self.wifi_dut.interfaces.wifi.azure_iot_disconnect()
            self.init = False
        if self.socket:
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock_id)
            self.socket = False
        self.azure_iot_client.interfaces.device.disconnect()
        time.sleep(2)

    def join_to_ap(self):
        if self.device_id == "symmetric_device":
            self.wifi_dut.interfaces.wifi.clear_certificate(cert_index=0,
                                                            cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                            cert_identifier=Si91xCertIdentifier.
                                                            SL_NET_TLS_CLIENT_CREDENTIAL_START)
            self.wifi_dut.interfaces.wifi.clear_certificate(cert_index=0,
                                                            cert_type=Si91xCertificateType.SL_NET_PRIVATE_KEY,
                                                            cert_identifier=Si91xCertIdentifier.
                                                            SL_NET_TLS_CLIENT_CREDENTIAL_START)

        # self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

        logger().info("connecting to access point.....")
        self.dut_addr = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            retry_count=3,
            associated=self.wifi_dut.interfaces.wifi.associated,
            power_save=self.power_save,
        )
        self.dut_addr['ap_mac_address'] = self.wifi_access_point.interfaces.wifi.bssid

        result = self.wifi_dut.interfaces.wifi.dns_get(domain_name=self.host_name,
                                                       query_timeout=20000,
                                                       timeout=100)
        self.host_ip = (result.decode()).strip()

    def azure_iot_test(self, socket=True, init=True, subscribe=True, publish=True, receive=True, disconnect=True):

        if socket:
            self.connect_socket()
        if init:
            self.azure_iot_init()
        if subscribe:
            self.subscribe_from_dut()
        if publish:
            self.send_msg_from_device()
        if receive:
            self.send_msg_from_cloud()
        if disconnect:
            self.azure_iot_disconnect()


def wifi_dut_marker(ca_cert=None, client_cert=None, client_key=None):
    """
    Common method to generate wifi_dut marker for pytest.mark.config decorator.
    """
    config = {

            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default
            | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default
            | Si91xTCPIPFeatureBitMap.SSL
            | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
            | Si91xTCPIPFeatureBitMap.DNSClient
            | Si91xTCPIPFeatureBitMap.Ping,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
            | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
            | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
            | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
            | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
            | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
            | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": 0,
            "ble_features": 0,
            "ble_custom_ext_features": 0,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 2, "stack_len": 4096}},

    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if client_cert:
        config["client_cert"] = client_cert

    if client_key:
        config["client_key"] = client_key
    return pytest.mark.config("wifi_dut", wifi=config)

@pytest.mark.firmware_app("test_azure")
@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19515')
def test_azure_mqtt_subscribe_publish_C19515(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):

    """
    Test Description:
    This test case verifies the Azure MQTT subscribe and publish functionality.
    """
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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



@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19516')
def test_azure_mqtt_subscribe_recv_C19516(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):
    """
    Test Description:
    This test case verifies the Azure MQTT subscribe and receive functionality.
    """

    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        # azure_obj.send_msg_from_device(message=message)
        azure_obj.send_msg_from_cloud(message=message)
        azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()

        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        azure_iot_client.interfaces.device.disconnect()




@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19517')
def test_azure_mqtt_socket_close_C19517(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                        sl_collections, wifi_client, request, utf_constants, sniffer_filter):
    """
    Test Description:
    This test case verifies the Azure MQTT socket close functionality.
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        azure_obj.join_to_ap()
        repeat_count = iter_count if iter_count > 2 else 3
        for count in range(repeat_count):
            message = text_generator(size=10)
            logger().info(f"Message is:{message}")
            azure_obj.connect_socket()
            azure_obj.azure_iot_init()
            azure_obj.subscribe_from_dut()
            azure_obj.send_msg_from_device(message=message)
            azure_obj.send_msg_from_cloud(message=message)
            azure_obj.azure_iot_disconnect()

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        azure_iot_client.interfaces.device.disconnect()


@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19518')
def test_azure_mqtt_after_disconn_reconnect_AP_C19518(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                                      sl_collections, wifi_client, request, utf_constants,
                                                      sniffer_filter):
    """
    Test Description:
    This test case verifies the Azure MQTT socket close functionality.
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        repeat_count = iter_count if iter_count > 2 else 3
        for count in range(repeat_count):
            message = text_generator(size=10)
            logger().info(f"Message is:{message}")
            azure_obj.join_to_ap()
            azure_obj.connect_socket()
            azure_obj.azure_iot_init()
            azure_obj.subscribe_from_dut()
            azure_obj.send_msg_from_device(message=message)
            azure_obj.send_msg_from_cloud(message=message)
            azure_obj.azure_iot_disconnect()
            wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        azure_iot_client.interfaces.device.disconnect()





@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19535')
def test_azure_mqtt_iot_hub_symmetic_C19535(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                            sl_collections, wifi_client, request, utf_constants, sniffer_filter):
    """
    Test Description:
    This test case verifies the Azure MQTT functionality using symmetric authentication.
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        azure_obj.send_msg_from_cloud(message=message)
        azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        azure_iot_client.interfaces.device.disconnect()



#@pytest.mark.skip(reason="not working")
@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19524')
def test_azure_mqtt_receive_with_diff_sizes_C19524(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):

    """
    Test Description:
    This test case verifies the Azure MQTT subscribe and publish functionality wth different sizes of messages.
    """
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        azure_obj.join_to_ap()
        azure_obj.connect_socket()
        azure_obj.azure_iot_init()
        azure_obj.subscribe_from_dut()
        sizes_list = [1, 100, 500, 1000, 1390]
        for i in range(0, len(sizes_list)):
            message = text_generator(size=sizes_list[i])
            logger().info(f"Message is:{message}")
            azure_obj.send_msg_from_cloud(message=message, count=1, duration=120)
        azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        azure_iot_client.interfaces.device.disconnect()


@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C19537')
def test_azure_mqtt_device_id_missing_C19537(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):

    """
    Test Description:
    This test case verifies the Azure MQTT connection without device id in connection string.
    """
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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

        azure_obj.join_to_ap()
        azure_obj.connect_socket()
        try:
            wifi_dut.interfaces.wifi.azure_iot_init(
                hostname=azure_obj.host_name,
                device_id="NULL",
                port=4002,
                mode=0,
                symmetrickey=azure_obj.shared_key,
                #expected_status=SLStatus.SL_STATUS_FAIL,
                timeout=100)
            status = False
        except Exception as Ex:
            logger().info(f"Exception is: {Ex}")
            logger().info("Command failed as expected")
            status = True
        assert status, "command should fail as device id is missing in connection string"
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        azure_iot_client.interfaces.device.disconnect()



@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19541')
def test_azure_mqtt_disconnect_C19541(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                      sl_collections, wifi_client, request, utf_constants, sniffer_filter):

    """
    Test Description:
    This test case verifies the Azure MQTT subscribe and publish functionality.
    """
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        azure_obj.join_to_ap()
        repeat_count = iter_count if iter_count > 2 else 3
        for count in range(repeat_count):
            message = text_generator(size=10)
            logger().info(f"Message is:{message}")
            azure_obj.connect_socket()
            azure_obj.azure_iot_init()
            azure_obj.subscribe_from_dut()
            azure_obj.send_msg_from_device(message=message)
            azure_obj.send_msg_from_cloud(message=message)
            azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        azure_iot_client.interfaces.device.disconnect()



@pytest.mark.skip(reason="not working")
@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19523')
def test_azure_mqtt_publish_with_diff_sizes_C19523(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):

    """
    Test Description:
    This test case verifies the Azure MQTT subscribe and publish functionality wth different sizes of messages.
    """
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        azure_obj.join_to_ap()
        azure_obj.connect_socket()
        azure_obj.azure_iot_init()
        azure_obj.subscribe_from_dut()
        sizes_list = [1, 10, 100, 512, 1000] #
        for i in range(0, len(sizes_list)):
            message = text_generator(size=sizes_list[i])
            logger().info(f"Message is:{message}")
            azure_obj.send_msg_from_device(message=message, count=1)

        azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        azure_iot_client.interfaces.device.disconnect()



@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C19538')
def test_azure_mqtt_wrong_sharedkey_C19538(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                           sl_collections, wifi_client, request, utf_constants, sniffer_filter):

    """
    Test Description:
    This test case verifies the Azure MQTT connection with wrong shared key.
    """
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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

        azure_obj.join_to_ap()
        azure_obj.connect_socket()
        status = False
        try:
            wifi_dut.interfaces.wifi.azure_iot_init(
                hostname=azure_obj.host_name,
                device_id=azure_obj.device_id,
                port=4002,
                mode=0,
                symmetrickey="Vn0P8z6gqR5ShVvv6ouQOT0eAcQFQB9GLdddhf",
                timeout=100)
        except Exception as Ex:
            logger().info(f"Exception is: {Ex}")
            logger().info("Command failed as expected")
            status = True
        assert status, "command should fail as wrong wrong shared key is provided"
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        azure_iot_client.interfaces.device.disconnect()



@wifi_dut_marker(ca_cert=["ca-cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C19530')
def test_azure_mqtt_wrong_cert_C19530(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                           sl_collections, wifi_client, request, utf_constants, sniffer_filter):

    """
    Test Description:
    This test case verifies the Azure MQTT connection with wrong certificate.
    """
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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

        azure_obj.join_to_ap()

        status = False
        try:
            azure_obj.connect_socket()
        except Exception as Ex:
            logger().info(f"Exception is: {Ex}")
            logger().info("Command failed as expected")
            status = True
        assert status, "socket connection should fail as wrong cert is provided"
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        azure_iot_client.interfaces.device.disconnect()




@wifi_dut_marker(ca_cert=[
                "silabs_dgcert_ca.pem",
                "SL_NET_SIGNING_CERTIFICATE",
                "SL_NET_TLS_SERVER_CREDENTIAL_START",
            ])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19539')
def test_azure_mqtt_send_20_telemetry_messages_C19539(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):

    """
    Test Description:
    This test case verifies the Azure MQTT subscribe and publish functionality.
    """
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        azure_obj.send_msg_from_device(message=message, count=20)
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
    ca_cert=[
            "silabs_dgcert_ca.pem",
            "SL_NET_SIGNING_CERTIFICATE",
            "SL_NET_TLS_SERVER_CREDENTIAL_START",
    ],
    client_cert=[
        "mydevkitcertificate.pem",
        "SL_NET_CERTIFICATE",
        "SL_NET_TLS_CLIENT_CREDENTIAL_START",
    ],
    client_key=[
        "mydevkitkey.pem",
        "SL_NET_PRIVATE_KEY",
        "SL_NET_TLS_CLIENT_CREDENTIAL_START",
    ],
)
@pytest.mark.config(
    "azure_iot", wifi={"device": "x509_device", "device_id": "x.509_self_signed_sha1"}
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19514')
def test_azure_mqtt_ssl_auth_C19514(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                    sl_collections, wifi_client, request, utf_constants, sniffer_filter):
    """
    Test Description:
    This test case verifies the Azure MQTT functionality using x.509 authentication.
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        iter_count = utf_constants.get("iter_count")
        message = text_generator(size=10)
        logger().info(f"Message is:{message}")
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
            device_id="x509_device",
        )

        azure_obj.join_to_ap()
        azure_obj.azure_iot_connect()
        azure_obj.subscribe_from_dut()
        azure_obj.send_msg_from_device(message=message)
        azure_obj.send_msg_from_cloud(message=message)
        azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()
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
    ca_cert=[
            "silabs_dgcert_ca.pem",
            "SL_NET_SIGNING_CERTIFICATE",
            "SL_NET_TLS_SERVER_CREDENTIAL_START",
    ],
    client_cert=[
        "mydevkitcertificate.pem",
        "SL_NET_CERTIFICATE",
        "SL_NET_TLS_CLIENT_CREDENTIAL_START",
    ],
    client_key=[
        "mydevkitkey.pem",
        "SL_NET_PRIVATE_KEY",
        "SL_NET_TLS_CLIENT_CREDENTIAL_START",
    ],
)
@pytest.mark.config(
    "azure_iot", wifi={"device": "x509_device", "device_id": "x.509_self_signed_sha1"}
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19536')
def test_azure_iot_x_509_self_signed_C19536(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                    sl_collections, wifi_client, request, utf_constants, sniffer_filter):
    """
    Test Description:
    This test case verifies the Azure MQTT functionality using x.509 authentication.
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
            device_id="x509_device",
        )
        message = text_generator(size=10)
        logger().info(f"Message is:{message}")
        azure_obj.join_to_ap()
        azure_obj.azure_iot_connect()
        azure_obj.subscribe_from_dut()
        azure_obj.send_msg_from_device(message=message)
        azure_obj.send_msg_from_cloud(message=message)
        azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()
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
    ca_cert=[
            "silabs_dgcert_ca.pem",
            "SL_NET_SIGNING_CERTIFICATE",
            "SL_NET_TLS_SERVER_CREDENTIAL_START",
    ],
    client_cert=[
        "mydevkitcertificate.pem",
        "SL_NET_CERTIFICATE",
        "SL_NET_TLS_CLIENT_CREDENTIAL_START",
    ],
    client_key=[
        "mydevkitkey.pem",
        "SL_NET_PRIVATE_KEY",
        "SL_NET_TLS_CLIENT_CREDENTIAL_START",
    ],
)
@pytest.mark.skip(reason="send and receive message is not working")
@pytest.mark.config(
    "azure_iot", wifi={"device": "x509_device", "device_id": "x.509_self_signed_sha1"}
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19543')
def test_azure_iot_ssl_auth_send_recv_C19543(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                    sl_collections, wifi_client, request, utf_constants, sniffer_filter):
    """
    Test Description:
    This test case verifies the Azure MQTT functionality using x.509 authentication and send and receive messages
     on subscribed topic parallelly.
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
            device_id="x509_device",
        )
        message = text_generator(size=10)
        logger().info(f"Message is:{message}")
        azure_obj.join_to_ap()
        azure_obj.azure_iot_connect()
        azure_obj.subscribe_from_dut()

        send_thread = Thread(target=azure_obj.send_msg_from_device, args=(message, 5, 60), )
        recv_thread = Thread(target=azure_obj.send_msg_from_cloud, args=(message, 5, 3, 120), )
        send_thread.start()
        recv_thread.start()
        send_thread.join()
        recv_thread.join()

        azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        azure_iot_client.interfaces.device.disconnect()


@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4176")
@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19540')
def test_azure_mqtt_recv_timeout_C19540(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):
    """
    Test Description:
    This test case verifies the Azure MQTT subscribe and receive functionality.
    """

    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        status = False
        try:
            wifi_dut.interfaces.wifi.azure_iot_recv(maxcount=1, maxtry=1, timeout=120)
            status = False
        except Exception as err:
            logger().warning(f"Failed to receive published message in DUT\n{err}")
            if "0x7" in str(err):
                logger().info("Timeout occurred, expected error code received")
                status = True
            else:
                logger().info("expected error code not received")
                raise
        assert status, "DUT receive should fail with error 0X0007, timeout error"

        azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()

        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        azure_iot_client.interfaces.device.disconnect()




@pytest.mark.skip(reason="AZURE pusblish is not working for long run testcases")
@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19522')
def test_azure_mqtt_subscribe_publish_30m_C19522(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):

    """
    Test Description:
    This test case verifies the Azure MQTT subscribe and publish functionality for every 10mins upto 24 hours.
    """
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        azure_obj.join_to_ap()
        sw = Stopwatch()
        while sw.elapsed_sec < 30 * 60:
            message = text_generator(size=10)
            logger().info(f"Message is:{message}")
            azure_obj.azure_iot_connect()
            azure_obj.subscribe_from_dut()
            azure_obj.send_msg_from_device(message=message)
            azure_obj.azure_iot_disconnect()
            time.sleep(2)
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               azure_obj.dut_addr['dut_mac_address'],
                                               azure_obj.dut_addr['ap_mac_address'],
                                               sniffer_filter)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        azure_iot_client.interfaces.device.disconnect()


@pytest.mark.skip(reason="Test case is not ready")
@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19531')
def test_azure_mqtt_subscribe_publish_24hrs_C19531(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):

    """
    Test Description:
    This test case verifies the Azure MQTT subscribe and publish functionality for every 10mins upto 24 hours.
    """
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        azure_obj.join_to_ap()
        azure_obj.azure_iot_connect()
        azure_obj.subscribe_from_dut()
        sw = Stopwatch()
        send_count = 0
        message = text_generator(size=10)
        logger().info(f"Message is:{message}")
        azure_iot_client.interfaces.hub.received_messages.clear()
        with azure_iot_client.interfaces.hub.start_receiving_events(duration=10):
            while sw.elapsed_sec < 86400:
                azure_obj.publish_from_dut(count=3, message=message, timeout=60)
                send_count += 3
                time.sleep(600)

        assert message in azure_iot_client.interfaces.hub.received_messages, \
            "message sent from device not received on cloud"
        logger().info(f"message sent from device received on cloud {message}")
        received_msgs = azure_iot_client.interfaces.hub.received_messages

        assert received_msgs.count(message) == send_count, \
            "Number of times message sent from device not received on cloud"
        logger().info(f"Number of times message sent from device {send_count} received on cloud"
                      f" {received_msgs.count(message)}")
        # azure_obj.send_msg_from_device(message=message, count=1)
        #time.sleep(60)
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



@pytest.mark.skip(reason="Test case is not ready")
@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C19532')
def test_azure_mqtt_subscribe_recv_24hrs_C19532(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):

    """
    Test Description:
    This test case verifies the Azure MQTT subscribe and recv functionality for every 1hr upto 24 hours.
    """
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        sw = Stopwatch()
        while sw.elapsed_sec < 1800:
            azure_obj.send_msg_from_cloud(message=message)
            time.sleep(100)
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


@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
@pytest.mark.test_src_map_id('C562270')
def test_azure_functionality_with_different_hubs_562270(wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_clients,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):

    """
    Test Description:
    This test case verifies the Azure MQTT subscribe and recv functionality for every 1hr upto 24 hours.
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        logger().info("Initiating {index} HUB connection")
        azure_obj_2 = Azure_iot_Thread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            test_case=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            azure_iot_clients=azure_iot_clients[1],
            device_id="Silabs_Device_Azure_IOT",
        )

        message = text_generator(size=10)
        logger().info(f"Message is:{message}")
        azure_obj_2.join_to_ap()
        azure_obj_2.connect_socket()
        azure_obj_2.azure_iot_init()
        azure_obj_2.subscribe_from_dut()
        logger().info(f"Initiating sending of message to 2nd HUB")

        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            azure_obj_2.send_msg_from_device(message=message)
            logger().info(f"msg from DUT to cloud is sent to 2nd HUB")
            time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        azure_obj_2.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()
