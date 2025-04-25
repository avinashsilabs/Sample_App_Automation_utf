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
    Si91xCustomSyncSockOptParms,
    Si91xBLECustomFeatureBitMap, Si91xCertificateType, Si91xCertIdentifier,
)
from utf.utf_config import UtfConfig
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.utils.iperf.iperf_utils import ping

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. AZURE IOT HUB Account
		6. PDU switch 

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and get ip through DHCP
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from/to the dut address
        5. Create the socket and connect to the azure iot hub
        6. Subscribe to the topic, send the message and receive the message
		7.turn off PDU switch of third party AP after some time delay turn it on
		8.close previous socket and open new socket and connect it
		9.try to do dut_rx to that socket for some time
		10.verify window size of RX_packet is 64k or not


    Author: Vasavi Kalla

"""

def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

class Azure_Thread():
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, ping_count=None, test_case=None, net_perf_client=None,switch=None,
                 sl_collections=None, sniffer_filter=None, power_save=None, ap_mac_address=None, azure_iot_client=None, data=None,
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
        self.second_time = 0
        self.switch=switch
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
        self.wifi_dut.interfaces.wifi.azure_iot_init(
            hostname=self.host_name,
            device_id=self.device_id,
            port=4002,
            mode=0,
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

    def rejoin_dut_to_ap(self):
        logger().info('***** Turn off Access point *****')
        self.switch.interfaces.pdu_switch.turn_off(delay=60)
        # time.sleep(60)

        logger().info('******* Turn on Access point **********')
        self.switch.interfaces.pdu_switch.turn_on(delay=60)
        # time.sleep(60)
        self.second_time = 1
        logger().info('******* Trying to reconnect DUT and resume data transfer **********')

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
        if self.second_time == 1:
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock_id, timeout=20)
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
            self.wifi_dut.interfaces.wifi.leave()
            self.socket = False
        self.azure_iot_client.interfaces.device.disconnect()
        time.sleep(2)

    def join_to_ap(self):
        if self.second_time == 1:
            logger().info(f"dut is in rejoin state now")
        else:
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
            power_save=False,
        )
        self.dut_addr['ap_mac_address'] = self.wifi_access_point.interfaces.wifi.bssid

        if self.second_time == 1:
            for i in range(0, 3):
                result = self.wifi_dut.interfaces.wifi.dns_get(domain_name=self.host_name,
                                                                   query_timeout=20000,
                                                                   timeout=100)
                self.host_ip = (result.decode()).strip()
                if self.host_ip is not None:
                    break
        else:
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
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.WPSSupportDisabled
            | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default
            | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DHCPv4Client
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
@pytest.mark.test_src_map_id('c37599')
def test_azure_mqtt_TCP_rx_window_size_64k_after_rejoin_c37599(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                                      sl_collections, wifi_client, utf_constants, request, switch,
                                                      sniffer_filter):
    """
    Test Description:
    Verify TCP Rx window size as 64K after join and  rejoin remains same  using AZURE MQTT application after rejoin functionality.
    """

    try:
        test_name = "c37599"
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
            switch=switch,
        )
        message = text_generator(size=10)
        logger().info(f"Message is:{message}")
        azure_obj.join_to_ap()
        azure_obj.connect_socket()
        azure_obj.azure_iot_init()
        azure_obj.subscribe_from_dut()
        azure_obj.send_msg_from_cloud(message=message)
        azure_obj.rejoin_dut_to_ap()
        azure_obj.azure_iot_disconnect()
        wifi_access_point.interfaces.wifi.start_ap()
        azure_obj.join_to_ap()
        azure_obj.azure_iot_connect()
        azure_obj.subscribe_from_dut()
        azure_obj.send_msg_from_cloud(message=message)
        azure_obj.azure_iot_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=azure_obj.dut_addr['dut_mac_address'],
                                                                                        filter_name="rx_window_size")
        logger().info(f"Validate window_size as 64k in rx request packet of DUT")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1),\
            f'Unable to find window_size as 64k in rx request packet of DUT'

        logger().info(f"found window_size as 64k in rx request packet of DUT")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        azure_iot_client.interfaces.device.disconnect()
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=0, timeout=20)
        logger().info('******* Turn on Access point **********')
        self.switch.interfaces.pdu_switch.turn_on(delay=60)