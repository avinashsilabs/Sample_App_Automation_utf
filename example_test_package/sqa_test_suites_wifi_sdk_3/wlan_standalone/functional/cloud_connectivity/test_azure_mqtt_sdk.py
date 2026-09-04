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
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces import AsyncEventIdentifiers

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

    Every constant, helper and marker used by the test cases is defined on
    ``AzureMqtt``; the test functions below only reach them through that class.

    Author: Swathi.Chinthala
"""

class AzureMqtt(ThreadBase):
    """Wi-Fi join, TLS socket, and Azure IoT Hub MQTT session for SDK tests."""

    FIRMWARE_APP = "test_azure"
    CLOUD_TELEMETRY_TIMEOUT = 90
    POWER_SAVE_PROFILE = "power_save_low_latency"
    HIGH_PERFORMANCE_PROFILE = "high_performance"
    X509_DEVICE_ID = "x509-Aug-2026"
    AZURE_APP_PORT = 4002
    MQTT_TLS_PORT = 8883
    END_STATE = [
        "wifi_powersave_disable",
        "azure_iot_unsubscribe",
        "azure_iot_disconnect",
        "disassociated",
    ]
    AP_CONFIG = {"security": "WPA2", "password": "12345678"}
    CA_CERT_SILABS = [
        "silabs_dgcert_ca.pem",
        "SL_NET_SIGNING_CERTIFICATE",
        "SL_NET_TLS_SERVER_CREDENTIAL_START",
    ]

    def __init__(
        self,
        wifi_dut=None,
        wifi_access_point=None,
        wifi_sniffer=None,
        ping_count=None,
        test_case=None,
        sl_collections=None,
        sniffer_filter=None,
        power_save=None,
        ap_mac_address=None,
        azure_iot_client=None,
        azure_iot_clients=None,
        wifi_client=None,
        test_type=None,
        disconnect=True,
        device_id="symmetric_device",
        switch=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ping_count = ping_count
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.sniffer_filter = sniffer_filter
        self.azure_iot_client = azure_iot_client or azure_iot_clients
        self.wifi_client = wifi_client
        self.dut_addr = None
        self.ap_mac_address = ap_mac_address
        self.test_type = test_type
        self.disconnect = disconnect
        self.device_id = device_id
        self.switch = switch
        self.sock_id = None
        self.host_ip = None
        self.socket, self.init, self.subscribe = False, False, False
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        self.logger.info(f"in harness power_save flag set to be : {self.power_save}")
        self.connection_string = self.azure_iot_client.interfaces.device.config[
            "connection_string_device"
        ]
        [(self.host_name, self.device, self.shared_key)] = re.findall(
            r"HostName=(.*);DeviceId=(.*);SharedAccessKey=(.*)",
            self.connection_string,
        )

    @classmethod
    def wifi_dut_marker(cls, ca_cert=None, client_cert=None, client_key=None):
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

    @staticmethod
    def text_generator(size=200):
        return "".join(
            random.choice(string.ascii_uppercase + string.digits) for _ in range(size)
        )

    def verify_telemetry_on_cloud(
        self, hub, message, count, publish, cloud_timeout=None
    ):
        """Publish from the DUT and wait until the hub surfaces the telemetry."""
        if cloud_timeout is None:
            cloud_timeout = self.CLOUD_TELEMETRY_TIMEOUT
        hub.received_messages.clear()

        with hub.start_receiving_events(duration=10):
            publish()
            sw = Stopwatch()
            while sw.elapsed_sec < cloud_timeout:
                if hub.received_messages.count(message) >= count:
                    break
                time.sleep(2)
            self.logger.info(
                f"waited {sw.elapsed_sec:.0f}s for telemetry to reach the cloud"
            )

        received_msgs = hub.received_messages
        assert message in received_msgs, "message sent from device not received on cloud"
        self.logger.info(f"message sent from device received on cloud {message}")
        assert received_msgs.count(message) == count, (
            "Number of times message sent from device not received on cloud"
        )
        self.logger.info(
            f"Number of times message sent from device {count} received on cloud"
            f" {received_msgs.count(message)}"
        )

    @retry(Exception, delay=5, tries=2)
    def subscribe_from_dut(self, timeout=120):
        self.wifi_dut.interfaces.wifi.azure_iot_subscribe(timeout=timeout)
        self.subscribe = True
        time.sleep(3)

    @retry(Exception, delay=5, tries=2)
    def publish_from_dut(self, count=1, message="hello", timeout=120):
        self.wifi_dut.interfaces.wifi.azure_iot_publish(
            payload=message, maxcount=count, timeout=timeout
        )

    def receive_messages_from_dut(self, retries=2, wait_time=3, maxtry=3):
        for retry_count in range(retries):
            try:
                time.sleep(wait_time)
                recv_msg = self.wifi_dut.interfaces.wifi.azure_iot_recv(
                    maxcount=1, maxtry=maxtry, timeout=120
                )
                assert len(recv_msg), "Failed to receive published message in DUT"
                return recv_msg[-1]
            except Exception as err:
                self.logger.warning(
                    f"Failed to receive published message in DUT\n{err}"
                )
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
            self.device_id = self.X509_DEVICE_ID
            mode = 1
            self.shared_key = None
        else:
            mode = 0
        self.wifi_dut.interfaces.wifi.azure_iot_init(
            hostname=self.host_name,
            device_id=self.device_id,
            port=self.AZURE_APP_PORT,
            mode=mode,
            symmetrickey=self.shared_key,
            timeout=timeout,
        )
        self.init = True
        self.logger.info("azure iot init successful")

    def send_msg_from_cloud(self, message="Sending_c2d_message", count=3, maxtry=10, duration=120):
        for i in range(count):
            self.logger.info(f"Sending message from cloud to device :{message}")
            recv_msg = self.recv_from_cloud(message)
            assert message == recv_msg, "Failed to receive published message in DUT"
            time.sleep(2)

    def send_msg_from_device(self, message="Sending_d2c_message", count=3, duration=60):
        self.verify_telemetry_on_cloud(
            self.azure_iot_client.interfaces.hub,
            message,
            count,
            lambda: self.publish_from_dut(count=count, message=message, timeout=duration),
        )

    def publish_with_session_recovery(self, message, count=1, duration=60):
        """Publish once, re-establishing the MQTT session first if it has gone stale."""
        try:
            self.send_msg_from_device(message=message, count=count, duration=duration)
            return
        except Exception as ex:
            self.logger.warning(f"publish failed, re-establishing azure session: {ex}")
        self.reconnect_azure_session()
        self.send_msg_from_device(message=message, count=count, duration=duration)

    def recv_from_cloud_with_session_recovery(self, message, settle_sec=10, retries=3, wait_time=3):
        """Send a C2D message and read it back on the DUT, recovering a stale session."""
        try:
            return self.recv_from_cloud(
                message, settle_sec=settle_sec, retries=retries, wait_time=wait_time
            )
        except Exception as ex:
            self.logger.warning(f"recv failed, re-establishing azure session: {ex}")
        self.reconnect_azure_session()
        return self.recv_from_cloud(
            message, settle_sec=settle_sec, retries=retries, wait_time=wait_time
        )

    def recv_from_cloud(self, message, settle_sec=10, retries=3, wait_time=3):
        self.azure_iot_client.interfaces.hub.send_message_to_device(self.device_id, message)
        time.sleep(settle_sec)
        return self.receive_messages_from_dut(retries=retries, wait_time=wait_time)

    def reconnect_azure_session(self, settle_sec=5):
        """Drop the DUT MQTT session and bring it back up on a fresh socket."""
        self.teardown_dut_session()
        time.sleep(settle_sec)
        self.azure_iot_connect()
        self.subscribe_from_dut()

    def connect_socket(self, rcv_tv_sec="0", rcv_tv_usec="2000"):
        """Open TLS socket to Azure; configure rsi_recv timeout via SO_RCVTIMEO."""
        self.sock_id = self.wifi_dut.interfaces.wifi.socket(
            "AF_INET", "SOCK_STREAM", "IPPROTO_TCP"
        )
        self.socket = True
        try:
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
                self.sock_id, "SOL_TCP", "TCP_ULP", "tls"
            )
            self.logger.info(
                f"Configuring rsi_recv / SO_RCVTIMEO: tv_sec={rcv_tv_sec}, tv_usec={rcv_tv_usec}"
            )
            self.wifi_dut.interfaces.wifi.bsdSetSocketOption(
                socket_fd=self.sock_id,
                option_level="SOL_SOCKET",
                option_name="SO_RCVTIMEO",
                tv_sec=str(rcv_tv_sec),
                tv_usec=str(rcv_tv_usec),
            )
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                self.sock_id, self.host_ip, 4, self.MQTT_TLS_PORT
            )
        except Exception:
            self.close_socket()
            raise
        time.sleep(5)

    def azure_iot_connect(self, retries=3, rcv_tv_sec="0", rcv_tv_usec="2000", retry_delay=10):
        """Open the TLS socket and bring up the Azure MQTT session."""
        for attempt in range(retries):
            relax_power_save = bool(self.power_save) and attempt > 0
            if relax_power_save:
                self.logger.info("Suspending power save for azure iot connect retry")
                self.wifi_dut.interfaces.wifi.set_performance_profile(
                    self.HIGH_PERFORMANCE_PROFILE
                )
            try:
                self.connect_socket(rcv_tv_sec=rcv_tv_sec, rcv_tv_usec=rcv_tv_usec)
                self.azure_iot_init()
                return
            except Exception as ex:
                self.logger.warning(
                    f"azure iot connect attempt {attempt + 1}/{retries} failed: {ex}"
                )
                self.teardown_dut_session()
                if attempt < retries - 1:
                    time.sleep(retry_delay)
            finally:
                if relax_power_save:
                    self.wifi_dut.interfaces.wifi.set_performance_profile(
                        self.POWER_SAVE_PROFILE
                    )
        raise AssertionError("Failed to connect to azure iot")

    def close_socket(self):
        """Close the DUT socket if one is open, tolerating a failing close."""
        if self.sock_id is None:
            return
        try:
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock_id)
        except Exception as ex:
            self.logger.warning(f"socket close for fd {self.sock_id} ignored: {ex}")
        finally:
            self.sock_id = None
            self.socket = False

    def teardown_dut_session(self):
        """Unwind DUT-side MQTT and socket state, tolerating failures at each step."""
        if self.subscribe:
            try:
                self.wifi_dut.interfaces.wifi.azure_iot_unsubscribe()
            except Exception as ex:
                self.logger.warning(
                    f"azure_iot_unsubscribe during teardown ignored: {ex}"
                )
            self.subscribe = False
        if self.init:
            try:
                self.wifi_dut.interfaces.wifi.azure_iot_disconnect()
            except Exception as ex:
                self.logger.warning(
                    f"azure_iot_disconnect during teardown ignored: {ex}"
                )
            self.init = False
        self.close_socket()

    def azure_iot_disconnect(self):
        self.teardown_dut_session()
        self.azure_iot_client.interfaces.device.disconnect()
        time.sleep(2)

    def force_ap_disconnect(self, settle_sec=5, rejoin_fail_timeout=180):
        """Simulate rejoin-fail the same way as the rejoin suite (PDU AP power cycle)."""
        assert self.switch is not None, (
            "PDU switch fixture required to simulate rejoin fail (same as rejoin tests)"
        )
        self.logger.info("Simulating rejoin fail: PDU power-off AP (not wifi.leave)")
        self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=2,
            scan_interval=6,
            beacon_missed_count=40,
            first_time_retry_enable=0,
        )
        self.switch.interfaces.pdu_switch.turn_off(delay=10)

        self.logger.info("Waiting for DUT REJOIN_EVENT (rejoin fail)...")
        sw = Stopwatch()
        saw_rejoin_fail = False
        while sw.elapsed_sec < rejoin_fail_timeout:
            events = self.wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT:
                    self.logger.info(f"Got rejoin fail event: {event.event_data}")
                    saw_rejoin_fail = True
                    break
            if saw_rejoin_fail:
                break
            time.sleep(0.1)
        assert saw_rejoin_fail, (
            f"REJOIN_EVENT not received within {rejoin_fail_timeout}s after AP PDU off"
        )

        self.logger.info("Turning AP back on after rejoin fail")
        self.switch.interfaces.pdu_switch.turn_on(delay=60)
        try:
            self.wifi_access_point.interfaces.wifi.start_ap()
        except Exception as ex:
            self.logger.info(f"start_ap after PDU on ignored: {ex}")

        self.subscribe = False
        self.init = False
        self.socket, self.sock_id = False, None
        self.wifi_dut.interfaces.wifi.associated = False
        time.sleep(settle_sec)

    def rejoin_ap(self, settle_sec=5):
        """Successful rejoin: clean leave + join again (not rejoin-fail)."""
        self.logger.info("Successful rejoin: leave AP then join again")
        try:
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as ex:
            self.logger.warning(f"leave during rejoin ignored: {ex}")
        self.subscribe = False
        self.init = False
        self.socket, self.sock_id = False, None
        time.sleep(settle_sec)
        self.logger.info("Rejoining AP after disconnect")
        self.join_to_ap()

    def join_to_ap(self):
        if self.device_id == "symmetric_device":
            self.wifi_dut.interfaces.wifi.clear_certificate(
                cert_index=0,
                cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
            )
            self.wifi_dut.interfaces.wifi.clear_certificate(
                cert_index=0,
                cert_type=Si91xCertificateType.SL_NET_PRIVATE_KEY,
                cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
            )

        self.logger.info("connecting to access point.....")
        self.dut_addr = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            retry_count=3,
            associated=self.wifi_dut.interfaces.wifi.associated,
            power_save=self.power_save,
        )
        self.dut_addr["ap_mac_address"] = self.wifi_access_point.interfaces.wifi.bssid
        self.resolve_host_ip()

    def resolve_host_ip(self, attempts=4, delay=5):
        """Resolve the IoT hub hostname on the DUT."""
        last_exc = None
        for attempt in range(attempts):
            relax_power_save = bool(self.power_save) and attempt > 0
            if relax_power_save:
                self.logger.info("Suspending power save for DNS retry")
                self.wifi_dut.interfaces.wifi.set_performance_profile(
                    self.HIGH_PERFORMANCE_PROFILE
                )
            try:
                result = self.wifi_dut.interfaces.wifi.dns_get(
                    domain_name=self.host_name, query_timeout=20000, timeout=100
                )
                self.host_ip = (
                    result.decode() if isinstance(result, (bytes, bytearray)) else str(result)
                ).strip()
                self.logger.info(f"'{self.host_name}' resolved to {self.host_ip}")
                return self.host_ip
            except Exception as e:
                last_exc = e
                self.logger.warning(
                    f"DNS lookup attempt {attempt + 1} failed for '{self.host_name}': {e}"
                )
                time.sleep(delay)
            finally:
                if relax_power_save:
                    self.wifi_dut.interfaces.wifi.set_performance_profile(
                        self.POWER_SAVE_PROFILE
                    )
        raise last_exc

    def azure_iot_test(
        self,
        socket=True,
        init=True,
        subscribe=True,
        publish=True,
        receive=True,
        disconnect=True,
    ):
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


# ********************************************************************************************************************
pytestmark = [pytest.mark.firmware_app("test_azure")]
# ********************************************************************************************************************

@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19515')
@pytest.mark.legacy_deployed
@pytest.mark.WLAN_Dev_sanity_917
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
        azure_obj = AzureMqtt(
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

        message = AzureMqtt.text_generator(size=10)
        AzureMqtt.logger.info(f"Message is:{message}")
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



@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19516')
@pytest.mark.legacy_deployed
def test_azure_mqtt_subscribe_recv_C19516(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        azure_obj = AzureMqtt(
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
        message = AzureMqtt.text_generator(size=10)
        AzureMqtt.logger.info(f"Message is:{message}")
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


@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19519')
@pytest.mark.legacy_deployed
def test_azure_mqtt_connect_after_second_ap_connect_c19519(
    firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
    sl_collections, wifi_client, request, utf_constants, sniffer_filter, switch
):
    """C19519: Connect to Azure MQTT only after the second AP association.

    First AP session is lost due to rejoin fail (PDU AP power-off → REJOIN_EVENT →
    AP power-on). After the DUT joins the AP a second time, open TLS socket +
    Azure MQTT and verify traffic.
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        azure_obj = AzureMqtt(
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
        message = AzureMqtt.text_generator(size=20)

        # 1) First AP connect
        AzureMqtt.logger.info("Step 1: Join AP (first association)")
        azure_obj.join_to_ap()

        # 2) First session lost due to rejoin fail (PDU off → REJOIN_EVENT → PDU on)
        AzureMqtt.logger.info("Step 2: First connection lost due to rejoin fail (PDU AP cycle)")
        azure_obj.force_ap_disconnect()

        # 3) Second AP connect, then Azure MQTT
        AzureMqtt.logger.info("Step 3: Join AP (second association)")
        azure_obj.join_to_ap()
        AzureMqtt.logger.info("Step 4: Connect to Azure MQTT after second AP connect")
        azure_obj.azure_iot_connect()
        azure_obj.subscribe_from_dut()
        azure_obj.send_msg_from_device(message=message, count=1)
        azure_obj.send_msg_from_cloud(message=message, count=1)

        azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(
            wifi_access_point, wifi_sniffer, azure_obj.dut_addr['dut_mac_address'],
            azure_obj.dut_addr['ap_mac_address'], sniffer_filter
        )
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        azure_iot_client.interfaces.device.disconnect()
        try:
            switch.interfaces.pdu_switch.turn_on(delay=60)
        except Exception:
            pass


@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.parametrize("keep_alive_period", [60, 300, 600])
@pytest.mark.test_src_map_id('C19520')
@pytest.mark.legacy_deployed
def test_azure_mqtt_keep_alive_with_different_periods_c19520(
    firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client, keep_alive_period,
    sl_collections, wifi_client, request, utf_constants, sniffer_filter
):
    """
    Validate Azure MQTT session continuity across different idle keep-alive windows.
    """
    try:
        test_name = f"{request.node.name}_{keep_alive_period}"
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        azure_obj = AzureMqtt(
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
        message = AzureMqtt.text_generator(size=30)
        azure_obj.join_to_ap()
        azure_obj.azure_iot_connect()
        azure_obj.subscribe_from_dut()
        AzureMqtt.logger.info(f"Idling MQTT session for keep_alive_period={keep_alive_period} seconds")
        time.sleep(keep_alive_period)
        azure_obj.send_msg_from_device(message=message, count=1)
        azure_obj.send_msg_from_cloud(message=message, count=1)
        azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(
            wifi_access_point, wifi_sniffer, azure_obj.dut_addr['dut_mac_address'],
            azure_obj.dut_addr['ap_mac_address'], sniffer_filter
        )
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        azure_iot_client.interfaces.device.disconnect()


@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19527')
@pytest.mark.legacy_deployed
def test_azure_mqtt_recv_publish_after_rejoin_c19527(
    firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
    sl_collections, wifi_client, request, utf_constants, sniffer_filter, switch
):
    """C19527: After rejoin-fail (PDU) and second AP join, recv + publish QoS1.

    azure_iot_publish uses eAzureIoTHubMessageQoS1 in firmware.
    Steps:
      1. Join AP, connect Azure MQTT, subscribe
      2. Rejoin fail via PDU switch (AP off → REJOIN_EVENT → AP on)
      3. Join AP again, reconnect Azure MQTT and subscribe
      4. Recv happens after rejoin: C2D on subscribed topic (azure_iot_recv)
      5. Publish D2C telemetry (QoS1)
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        azure_obj = AzureMqtt(
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
        recv_message = AzureMqtt.text_generator(size=16)
        pub_message = AzureMqtt.text_generator(size=32)

        AzureMqtt.logger.info("Step 1: Join AP and establish Azure MQTT + subscribe")
        azure_obj.join_to_ap()
        azure_obj.azure_iot_connect()
        azure_obj.subscribe_from_dut()

        AzureMqtt.logger.info("Step 2: Rejoin fail via PDU switch (same as rejoin suite)")
        azure_obj.azure_iot_disconnect()
        azure_obj.force_ap_disconnect()

        AzureMqtt.logger.info("Step 3: Join AP again, reconnect Azure MQTT and subscribe")
        azure_obj.join_to_ap()
        azure_obj.azure_iot_connect()
        azure_obj.subscribe_from_dut()

        AzureMqtt.logger.info("Step 4: Recv on subscribed topic after rejoin (cloud → device)")
        AzureMqtt.logger.info(f"C2D message for post-rejoin recv: {recv_message}")
        got = azure_obj.recv_from_cloud(recv_message, settle_sec=15)
        assert got == recv_message, (
            f"Post-rejoin recv failed: expected '{recv_message}', got '{got}'"
        )
        AzureMqtt.logger.info(f"Post-rejoin recv OK: {got}")

        AzureMqtt.logger.info("Step 5: Publish with QoS1 (device → cloud)")
        azure_obj.send_msg_from_device(message=pub_message, count=1)

        azure_obj.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(
            wifi_access_point, wifi_sniffer, azure_obj.dut_addr['dut_mac_address'],
            azure_obj.dut_addr['ap_mac_address'], sniffer_filter
        )
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        azure_iot_client.interfaces.device.disconnect()
        try:
            switch.interfaces.pdu_switch.turn_on(delay=60)
        except Exception:
            pass




@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19517')
@pytest.mark.legacy_deployed
def test_azure_mqtt_socket_close_C19517(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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

        azure_obj = AzureMqtt(
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
            message = AzureMqtt.text_generator(size=10)
            AzureMqtt.logger.info(f"Message is:{message}")
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


@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19518')
@pytest.mark.legacy_deployed
def test_azure_mqtt_after_disconn_reconnect_AP_C19518(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        azure_obj = AzureMqtt(
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
            message = AzureMqtt.text_generator(size=10)
            AzureMqtt.logger.info(f"Message is:{message}")
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





@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19535')
@pytest.mark.legacy_deployed
def test_azure_mqtt_iot_hub_symmetic_C19535(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        azure_obj = AzureMqtt(
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
        message = AzureMqtt.text_generator(size=10)
        AzureMqtt.logger.info(f"Message is:{message}")
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



@pytest.mark.skip("validation pending")
@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19524')
@pytest.mark.legacy_deployed
def test_azure_mqtt_receive_with_diff_sizes_C19524(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        azure_obj = AzureMqtt(
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
            message = AzureMqtt.text_generator(size=sizes_list[i])
            AzureMqtt.logger.info(f"Message is:{message}")
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


@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C19537')
@pytest.mark.legacy_deployed
def test_azure_mqtt_device_id_missing_C19537(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        azure_obj = AzureMqtt(
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
            AzureMqtt.logger.info(f"Exception is: {Ex}")
            AzureMqtt.logger.info("Command failed as expected")
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



@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19541')
@pytest.mark.legacy_deployed
def test_azure_mqtt_disconnect_C19541(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        azure_obj = AzureMqtt(
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
            message = AzureMqtt.text_generator(size=10)
            AzureMqtt.logger.info(f"Message is:{message}")
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



@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19523')
def test_azure_mqtt_publish_with_diff_sizes_C19523(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        azure_obj = AzureMqtt(
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
        sizes_list = [1, 10, 100, 512, 1000, 1390]
        for i in range(0, len(sizes_list)):
            message = AzureMqtt.text_generator(size=sizes_list[i])
            AzureMqtt.logger.info(f"Message is:{message}")
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



@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C19538')
@pytest.mark.legacy_deployed
def test_azure_mqtt_wrong_sharedkey_C19538(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        azure_obj = AzureMqtt(
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
            AzureMqtt.logger.info(f"Exception is: {Ex}")
            AzureMqtt.logger.info("Command failed as expected")
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



@AzureMqtt.wifi_dut_marker(ca_cert=["ca-cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C19530')
@pytest.mark.legacy_deployed
def test_azure_mqtt_wrong_cert_C19530(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        azure_obj = AzureMqtt(
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
            AzureMqtt.logger.info(f"Exception is: {Ex}")
            AzureMqtt.logger.info("Command failed as expected")
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




@AzureMqtt.wifi_dut_marker(ca_cert=[
                "silabs_dgcert_ca.pem",
                "SL_NET_SIGNING_CERTIFICATE",
                "SL_NET_TLS_SERVER_CREDENTIAL_START",
            ])
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19539')
@pytest.mark.legacy_deployed
def test_azure_mqtt_send_20_telemetry_messages_C19539(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        azure_obj = AzureMqtt(
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
        message = AzureMqtt.text_generator(size=10)
        AzureMqtt.logger.info(f"Message is:{message}")
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



@AzureMqtt.wifi_dut_marker(
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
    "azure_iot", wifi={"device": "x509_device", "device_id": "x509-Aug-2026"}
)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19514')
def test_azure_mqtt_ssl_auth_C19514(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        message = AzureMqtt.text_generator(size=10)
        AzureMqtt.logger.info(f"Message is:{message}")
        azure_obj = AzureMqtt(
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



@AzureMqtt.wifi_dut_marker(
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
    "azure_iot", wifi={"device": "x509_device", "device_id": "x509-Aug-2026"}
)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19536')
@pytest.mark.deployed_25q2
def test_azure_iot_x_509_self_signed_C19536(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        azure_obj = AzureMqtt(
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
        message = AzureMqtt.text_generator(size=10)
        AzureMqtt.logger.info(f"Message is:{message}")
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






@AzureMqtt.wifi_dut_marker(
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
    "azure_iot", wifi={"device": "x509_device", "device_id": "x509-Aug-2026"}
)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19543')
def test_azure_iot_ssl_auth_send_recv_C19543(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
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
        azure_obj = AzureMqtt(
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
        message = AzureMqtt.text_generator(size=10)
        AzureMqtt.logger.info(f"Message is:{message}")
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


@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19540')
@pytest.mark.legacy_deployed
def test_azure_mqtt_recv_timeout_C19540(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):
    """C19540: rsi_recv / SO_RCVTIMEO timeout configuration.

    Configure socket receive timeout via bsdSetSocketOption(SO_RCVTIMEO),
    subscribe, then call azure_iot_recv with no cloud publish. Expect
    timeout error 0x7 (SL_STATUS_TIMEOUT) when rsi_recv expires.
    Steps:
      1. Join AP
      2. Connect TLS socket with SO_RCVTIMEO (tv_sec=5, tv_usec=0)
      3. Azure IoT init + subscribe
      4. azure_iot_recv with no C2D data → expect 0x7 timeout
    """

    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        azure_obj = AzureMqtt(
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

        # rsi_recv timeout: 5 seconds (tv_sec=5, tv_usec=0 → SO_RCVTIMEO)
        rcv_tv_sec, rcv_tv_usec = "5", "0"
        AzureMqtt.logger.info(
            f"C19540: Configure rsi_recv timeout SO_RCVTIMEO "
            f"tv_sec={rcv_tv_sec}, tv_usec={rcv_tv_usec}"
        )
        azure_obj.join_to_ap()
        azure_obj.azure_iot_connect(rcv_tv_sec=rcv_tv_sec, rcv_tv_usec=rcv_tv_usec)
        azure_obj.subscribe_from_dut()

        status = False
        try:
            # No cloud publish — recv must time out via configured SO_RCVTIMEO
            AzureMqtt.logger.info("Calling azure_iot_recv with no C2D data; expect rsi_recv timeout")
            recv_msgs = wifi_dut.interfaces.wifi.azure_iot_recv(maxcount=1, maxtry=1, timeout=120)
            # An expired SO_RCVTIMEO is reported by completing the recv with no cloud
            # message rather than by failing the command with 0x7.
            status = not recv_msgs
            if status:
                AzureMqtt.logger.info("recv completed with no message, rsi_recv timeout honoured")
            else:
                AzureMqtt.logger.info(f"unexpected message received on idle topic: {recv_msgs}")
        except Exception as err:
            AzureMqtt.logger.warning(f"Failed to receive published message in DUT\n{err}")
            if "0x7" in str(err):
                AzureMqtt.logger.info("Timeout occurred, expected error code 0x7 received (rsi_recv / SO_RCVTIMEO)")
                status = True
            else:
                AzureMqtt.logger.info("expected error code not received")
                raise
        assert status, "DUT receive should time out with no message or error 0X0007, rsi_recv timeout"

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




@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19522')
def test_azure_mqtt_subscribe_publish_30m_C19522(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):
    """C19522: Single Azure MQTT socket; publish only for 30 minutes.

    Connect + subscribe once; do not recreate the socket in the loop.
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        azure_obj = AzureMqtt(
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
        run_time = utf_constants.get("azure_publish_30m_run_time_sec") or (30 * 60)
        publish_interval = utf_constants.get("azure_publish_30m_interval_sec") or 60

        AzureMqtt.logger.info("C19522: Join AP, connect Azure MQTT once, subscribe once")
        azure_obj.join_to_ap()
        azure_obj.azure_iot_connect()
        azure_obj.subscribe_from_dut()

        sw = Stopwatch()
        pub_count = 0
        AzureMqtt.logger.info(
            f"C19522: Publish-only loop for {run_time}s "
            f"(interval={publish_interval}s); socket kept open"
        )
        while sw.elapsed_sec < run_time:
            message = AzureMqtt.text_generator(size=10)
            AzureMqtt.logger.info(f"Publish #{pub_count + 1}: {message} (elapsed={sw.elapsed_sec:.0f}s)")
            azure_obj.publish_with_session_recovery(message=message, count=1)
            pub_count += 1
            remaining = run_time - sw.elapsed_sec
            if remaining <= 0:
                break
            time.sleep(min(publish_interval, remaining))

        AzureMqtt.logger.info(f"C19522: Completed {pub_count} publishes over {sw.elapsed_sec:.0f}s")
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


@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19531')
@pytest.mark.skip("validation pending")
def test_azure_mqtt_subscribe_publish_24hrs_C19531(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):
    """C19531: Single Azure MQTT socket; publish only for 24 hours.

    Connect + subscribe once; publish periodically (default every 10 min).
    Do not recreate the socket in the loop.
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        azure_obj = AzureMqtt(
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
        run_time = 86400
        sleep_interval = 120

        AzureMqtt.logger.info("C19531: Join AP, connect Azure MQTT once, subscribe once")
        azure_obj.join_to_ap()
        azure_obj.azure_iot_connect()
        azure_obj.subscribe_from_dut()

        sw = Stopwatch()
        pub_count = 0
        AzureMqtt.logger.info(
            f"C19531: Publish-only loop for {run_time}s "
            f"(interval={sleep_interval}s); socket kept open"
        )
        while sw.elapsed_sec < run_time:
            message = AzureMqtt.text_generator(size=10)
            AzureMqtt.logger.info(f"Publish #{pub_count + 1}: {message} (elapsed={sw.elapsed_sec:.0f}s)")
            azure_obj.publish_with_session_recovery(message=message, count=1)
            pub_count += 1
            remaining = run_time - sw.elapsed_sec
            if remaining <= 0:
                break
            AzureMqtt.logger.info(f"Waiting {min(sleep_interval, remaining)}s before next publish")
            time.sleep(min(sleep_interval, remaining))

        AzureMqtt.logger.info(f"C19531: Completed {pub_count} publishes over {sw.elapsed_sec:.0f}s")
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


@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C19532')
@pytest.mark.skip("validation pending")
def test_azure_mqtt_subscribe_recv_24hrs_C19532(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter):
    """C19532: Single Azure MQTT socket; recv only for 24 hours.

    Connect + subscribe once; cloud→device recv periodically (default every 1 hr).
    Do not recreate the socket in the loop.
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        azure_obj = AzureMqtt(
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
        run_time = utf_constants.get("azure_sleep_recv_run_time_sec") or 86400
        recv_interval = utf_constants.get("azure_sleep_recv_interval_sec") or 3600

        AzureMqtt.logger.info("C19532: Join AP, connect Azure MQTT once, subscribe once")
        azure_obj.join_to_ap()
        azure_obj.azure_iot_connect()
        azure_obj.subscribe_from_dut()

        sw = Stopwatch()
        recv_count = 0
        AzureMqtt.logger.info(
            f"C19532: Recv-only loop for {run_time}s "
            f"(interval={recv_interval}s); socket kept open"
        )
        while sw.elapsed_sec < run_time:
            message = AzureMqtt.text_generator(size=10)
            AzureMqtt.logger.info(f"Recv #{recv_count + 1}: C2D '{message}' (elapsed={sw.elapsed_sec:.0f}s)")
            got = azure_obj.recv_from_cloud_with_session_recovery(message)
            assert got == message, (
                f"Recv failed at #{recv_count + 1}: expected '{message}', got '{got}'"
            )
            recv_count += 1
            remaining = run_time - sw.elapsed_sec
            if remaining <= 0:
                break
            AzureMqtt.logger.info(f"Waiting {min(recv_interval, remaining)}s before next recv")
            time.sleep(min(recv_interval, remaining))

        AzureMqtt.logger.info(f"C19532: Completed {recv_count} recvs over {sw.elapsed_sec:.0f}s")
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


@AzureMqtt.wifi_dut_marker(ca_cert=AzureMqtt.CA_CERT_SILABS)
@pytest.mark.config(
    "wifi_access_point", wifi=AzureMqtt.AP_CONFIG
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=AzureMqtt.END_STATE)
@pytest.mark.test_src_map_id('C562270')
@pytest.mark.legacy_deployed
def test_azure_functionality_with_different_hubs_562270(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_clients,
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

        AzureMqtt.logger.info("Initiating {index} HUB connection")
        azure_obj_2 = AzureMqtt(
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

        message = AzureMqtt.text_generator(size=10)
        AzureMqtt.logger.info(f"Message is:{message}")
        azure_obj_2.join_to_ap()
        azure_obj_2.connect_socket()
        azure_obj_2.azure_iot_init()
        azure_obj_2.subscribe_from_dut()
        AzureMqtt.logger.info(f"Initiating sending of message to 2nd HUB")

        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            azure_obj_2.send_msg_from_device(message=message)
            AzureMqtt.logger.info(f"msg from DUT to cloud is sent to 2nd HUB")
            time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        azure_obj_2.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.leave()

