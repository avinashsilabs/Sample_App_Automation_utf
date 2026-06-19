from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils import print_dict, get_tls_certificate_dir
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xBTFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xJoinFeatureBitMap, Si91xCertificateType, \
    Si91xCertIdentifier, Si91xMqttQos
import time
import pytest
import uuid
import re
from typing import Optional
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.stopwatch import Stopwatch
import string
from random import choices
from utf.utils.iperf.iperf_utils import ping
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.shell.ssh_shell import SSHShell
import random

def logger():
    return get_logger(__name__)

class BleThreadFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_test_type=None, sl_collections=None, test_case=None,
                 ble_dut=None, ble_pairing=0, switch=None, utf_constants=None, bond_info=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_client_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.ble_pairing = ble_pairing
        self.switch = switch
        self.utf_constants = utf_constants
        self.bond_info = bond_info

    def run(self):
        """ *************************** Set up DUT for BLE advertising ***************************** """
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=self.ble_pairing,
                                                                            bond_info=self.bond_info)
        assert (self.ble_dut_address is not None), "Unable to fetch bluetooth address from DUT"
        logger().info(f" BLE DUT ADDRESS : {self.ble_dut_address}")
        time.sleep(5)

    def ble_disconnect(self, disconnect_from="remote"):
        self.sl_collections.ble_disconnect(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                           ble_dut_address=self.ble_dut_address,
                                           disconnect_from=disconnect_from, ble_client_address=self.ble_client_address)

    def scan_from_remote_device(self):
        bt_client_address = self.sl_collections.scan_from_remote_device(wifi_dut=self.wifi_dut,
                                                                        ble_client=self.ble_client,
                                                                        ble_dut_address=self.ble_dut_address)
        logger().info(f'bt_client_address is : {bt_client_address}')

    def master_connection(self):
        self.ble_client_address = self.sl_collections.ble_connection(
            wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
            timeout=20, mode='master')

        logger().info(f'wait for 60 seconds to check ble connection stability')
        time.sleep(60)
        self.wifi_dut.interfaces.wifi.ble_get_device_state()

    def slave_connection(self):
        self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)
        self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
            wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
            ble_pairing=self.ble_pairing)

        logger().info(f'wait for 60 seconds to check ble connection stability')
        time.sleep(60)
        self.wifi_dut.interfaces.wifi.ble_get_device_state()

    def multiple_ble_conn_intervals(self):
        connection_interval = [30, 125, 250, 500]
        BleThreadFunctionality.ble_client_address = self.sl_collections.check_ble_advertise_functionality(
            wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
            timeout=20)

        self.ble_client.interfaces.bluetooth.pair_and_connect(dev_addr=self.ble_dut_address)
        logger().info("updating connection params")
        time.sleep(10)

        for length in range(len(connection_interval)):
            logger().info(f'.... updating connection interval is : {connection_interval[length]} ....')
            self.ble_client.interfaces.bluetooth.hci_tool_manager.update_conn(
                dev_addr=self.ble_dut_address, min_conn_interval=int(int(connection_interval[length]) / 1.25),
                max_conn_interval=int(int(connection_interval[length]) / 1.25), conn_latency=0,
                supervision_timeout=3200)

    def ble_cleanup(self):
        self.sl_collections.cleanup_ble(
            ble_dut=self.wifi_dut, ble_client=self.ble_client, ble_client_address=self.ble_client_address)

    def ble_cleanup_disconn(self):
        logger().info("Checking connection status of BLE")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            time.sleep(5)
        elif state_int == 2:
            logger().info("Device is in scanning status try to stop scanning")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
        elif state_int == 1:
            logger().info("Device is in advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 3:
            logger().info("Device is in scanning status try to stop scanning")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
            logger().info("Device is advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 9:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            time.sleep(5)
            logger().info("Device is in advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 10:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            logger().info("Device is advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
        elif state_int == 0:
            logger().info("Device is in idle status")
        else:
            logger().info("Device is in unknown state")
            self.ble_dut.interfaces.bluetooth.is_dut_bad_state = True
        self.ble_client.interfaces.bluetooth.remove_device(self.ble_dut_address)
        self.ble_client.interfaces.bluetooth.close()
        logger().info(" *************DUT Cleanup Success *******************")


class BleNotifyTxThread(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client_address=None, payload_length=20, interval_s=2):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client_address = ble_client_address
        self.payload_length = payload_length
        self.interval_s = interval_s
        self.sent_count = 0

    def run(self):
        while not self.stop_requested:
            last_error = None
            for attempt in range(1, 6):
                if self.stop_requested:
                    return
                notify_data_address = None
                try:
                    notify_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.payload_length))
                    notify_data_address = self.wifi_dut.interfaces.wifi.allocate_memory(size=len(notify_data) + 1)
                    self.wifi_dut.interfaces.wifi.load_memory(
                        address=notify_data_address,
                        size=len(notify_data),
                        write_content=notify_data,
                    )
                    self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                        self.ble_client_address,
                        data=notify_data,
                        data_address=notify_data_address,
                    )
                    self.sent_count += 1
                    logger().info(f"Continuous BLE Tx count: {self.sent_count}")
                    last_error = None
                    break
                except Exception as ble_tx_ex:
                    last_error = ble_tx_ex
                    logger().warning(f"Continuous BLE Tx attempt {attempt}/5 failed: {ble_tx_ex}")
                    time.sleep(2)
                finally:
                    if notify_data_address is not None:
                        try:
                            self.wifi_dut.interfaces.wifi.memory_free(notify_data_address)
                        except Exception:
                            pass
            if last_error is not None:
                if self.stop_requested:
                    return
                raise last_error
            time.sleep(self.interval_s)

# this thread used for sta+ble as a slave
class BleDualRoleThreadFunctionality(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        ble_clients=None,
        ble_test_type=None,
        sl_collections=None,
        testcase=None,
        gatt=True,
        ble_pairing=0,
        max_conn_interval=160,
        min_conn_interval=160,
        bond_info=0
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_clients = ble_clients
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.testcase = testcase
        self.gatt = gatt
        self.ble_pairing = ble_pairing
        self.max_conn_interval = max_conn_interval
        self.min_conn_interval = min_conn_interval
        self.bond_info = bond_info

        if self.gatt:
            # Set up DUT for BLE advertising
            logger().info("start ble GATT service in DUT")
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
                set_smp=self.ble_pairing, bond_info=self.bond_info)
        else:
            # Set up DUT for BLE advertising
            logger().info("Initialising BLE")
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert (
            self.ble_dut_address is not None
        ), "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {self.ble_dut_address}")
        time.sleep(5)
        self.ble_clients_address = []

    def dual_role_disconnect(self):

        for i in range(0, len(self.ble_clients)):
            status = self.ble_clients[i].interfaces.bluetooth.get_connection_status(
                self.ble_dut_address
            )
            logger().info(
                f"Connection status in remote device '{self.ble_clients[0].name}' is:{status}"
            )
            assert (
                status
            ), f"Remote device '{self.ble_clients[i].name}' is not connected to DUT"
            self.wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=self.ble_clients_address[i]
            )
            self.ble_clients[i].interfaces.bluetooth.close()
            time.sleep(5)


    def run(self):
        self.ble_clients_address = []
        if self.ble_test_type == "slave_and_master":
            self.ble_clients_address.append(
                self.sl_collections.ble_connection(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_clients[0],
                    ble_dut_address=self.ble_dut_address,
                    mode="slave",
                )
            )

            self.ble_clients_address.append(
                self.sl_collections.ble_connection(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_clients[1],
                    ble_dut_address=self.ble_dut_address,
                    mode="master",
                )
            )

        if self.ble_test_type == "master_and_slave":
            self.ble_clients_address.append(
                self.sl_collections.ble_connection(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_clients[0],
                    ble_dut_address=self.ble_dut_address,
                    mode="master",
                )
            )
            self.ble_clients_address.append(
                self.sl_collections.ble_connection(
                        wifi_dut=self.wifi_dut,
                        ble_client=self.ble_clients[1],
                        ble_dut_address=self.ble_dut_address,
                        mode="slave"
                )
            )

class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, capture_filename=None, wifi_access_point=None, wifi_sniffer=None, mqtt_server=None
                 , mqtt_client=None, sl_collections=None, topic=None, sniffer_filter=None, message=None,
                 utf_constants=None, retry_count=1, disconnect_retry_count=1):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.capture_filename = capture_filename
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.sl_collections = sl_collections
        self.dut_addr = None
        self.topic = topic
        self.sniffer_filter = sniffer_filter
        self.message = message
        self.keep_alive_time = None
        self.utf_constants = utf_constants
        self.retry_count = retry_count
        self.disconnect_retry_count = disconnect_retry_count

    def run(self):
        try:
            if self.capture_filename is not None and self.wifi_sniffer is not None:
                logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
                self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.
                                                                         channel)
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")

            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)

            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     retry_count=self.retry_count)
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")

    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            disconnect_error = None
            for disconnect_attempt in range(1, self.disconnect_retry_count + 1):
                try:
                    logger().info(
                        f"disconnecting from AP before next iteration, attempt {disconnect_attempt}/{self.disconnect_retry_count}"
                    )
                    self.wifi_dut.interfaces.wifi.leave()
                    disconnect_error = None
                    break
                except Exception as disconnect_ex:
                    disconnect_error = disconnect_ex
                    logger().warning(
                        f"Wi-Fi disconnect attempt {disconnect_attempt}/{self.disconnect_retry_count} failed: {disconnect_ex}"
                    )
                    time.sleep(3)
            if disconnect_error is not None:
                raise disconnect_error

    def mqtt_connection(self):
        self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(25)
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(5)

    def mqtt_connection_ssl(self):
        self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", server_port=8883,
                                                                        is_connection_encrypted=True, is_retained=True)
        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(25)
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
        time.sleep(5)

    def subscribe_and_publish(self, qos):
        logger().info("MQTT Client subscribes to the topic")
        self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic, qos=qos)

        logger().info("DUT subscribes to the topic")
        self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic, qos=qos)

        time.sleep(5)

        logger().info("DUT publishes message over the topic")
        self.wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=self.topic, message=self.message, qos=qos, timeout=20)
        time.sleep(5)

    def rejoin_async_event(self):
        logger().info("Checking for rejoin fail event from dut")
        with TimeMeasurer() as t:
            sw = Stopwatch()
            while sw.elapsed_sec < 180:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                rejoin_error_events = [
                    event
                    for event in events
                    if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT
                ]
                if len(rejoin_error_events):
                    break
                time.sleep(0.1)
            else:
                return False

        logger().info(f"Received rejoin error event after {t.duration:.2f}s")
        return True

    def mqtt_keep_alive_check(
            self,
            dut_mac_address,
            test_case_name,
            decryption_key: Optional[str] = None,
            keep_alive_time_sec: Optional[float] = None,
    ):
        """Analyze capture for MQTT PUBACK (4) and PINGREQ (12), with WPA decrypt like get_mqtt_list.

        If no PINGREQ is seen, PINGRESP (13) timestamps are used as the keep-alive reference
        (immediate server response to the client ping).

        Ping timestamps closer than one keep-alive round-trip (e.g. PINGREQ + PINGRESP ~1s apart)
        are merged to one entry so interval checks compare successive *cycles*, not REQ vs RESP.
        """
        remote_capture_file = self.wifi_sniffer.interfaces.capture.remote_capture_file
        logger().info(f"capture file is:{remote_capture_file}")

        if decryption_key is None:
            decryption_key = (
                f"{self.wifi_access_point.interfaces.wifi.passphrase}:"
                f"{self.wifi_access_point.interfaces.wifi.ssid}"
            )

        test_case = test_case_name
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
        local_capture_file = (
            f"./reports/{test_case}_wlan_filter_{str(uuid.uuid4())[:8]}.pcap"
        )
        packet_filter1 = f"(wlan.addr == {dut_mac_address})"
        self.wifi_sniffer.interfaces.capture.shell(
            f"tshark -nr {remote_capture_file} -Y '{packet_filter1}' -T fields -e "
            f"frame.number -w {wlan_filter_file}"
        )
        if isinstance(self.wifi_sniffer.interfaces.capture.shell, SSHShell):
            with self.wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
                sftp.get(wlan_filter_file, local_capture_file)
            pcap_for_decrypt = local_capture_file
        else:
            pcap_for_decrypt = wlan_filter_file

        publish_ack = []
        ping_request = []
        ping_response = []
        dut_mac_lower = dut_mac_address.lower()

        def frame_time_relative(packet):
            try:
                return float(packet.frame_info.time_relative)
            except (AttributeError, ValueError, TypeError):
                try:
                    return float(packet.sniff_timestamp)
                except (AttributeError, ValueError, TypeError):
                    return None

        def mqtt_msgtype_from_layer(mqtt_layer):
            raw = getattr(mqtt_layer, "msgtype", None)
            if raw is not None:
                try:
                    return int(str(raw).strip().split()[0])
                except ValueError:
                    pass
            m = re.search(r"Message Type:.*?\((\d+)\)", str(mqtt_layer))
            return int(m.group(1)) if m else None

        logger().info("Parsing decrypted MQTT (PUBACK / PINGREQ / PINGRESP) from filtered capture")
        for packet in self.wifi_sniffer.interfaces.capture.iter_packets(
                decrypt_packets=True,
                encryption_type="WPA-PWD",
                decryption_key=decryption_key,
                capture_file_filter=pcap_for_decrypt,
        ):
            if not hasattr(packet, "wlan") or dut_mac_lower not in str(packet.wlan).lower():
                continue
            if not hasattr(packet, "mqtt"):
                continue
            msgtype = mqtt_msgtype_from_layer(packet.mqtt)
            if msgtype is None:
                continue
            trel = frame_time_relative(packet)
            if trel is None:
                continue
            if msgtype == 4:
                publish_ack.append(str(trel))
            elif msgtype == 12:
                ping_request.append(str(trel))
            elif msgtype == 13:
                ping_response.append(str(trel))

        if not ping_request and ping_response:
            logger().info(
                "No MQTT PINGREQ (msgtype 12) in capture; using PINGRESP (13) as keep-alive reference."
            )
            ping_request = ping_response

        if ping_request:
            if keep_alive_time_sec is not None and keep_alive_time_sec > 0:
                min_gap = max(5.0, keep_alive_time_sec * 0.25)
            else:
                min_gap = 10.0
            sorted_t = sorted(float(x) for x in ping_request)
            merged = [sorted_t[0]]
            for t in sorted_t[1:]:
                if t - merged[-1] >= min_gap:
                    merged.append(t)
            if len(merged) != len(ping_request):
                logger().info(
                    "Deduped ping-related timestamps: %d -> %d (min_gap=%.1fs, raw=%s, kept=%s)",
                    len(ping_request),
                    len(merged),
                    min_gap,
                    ping_request,
                    merged,
                )
            ping_request = [str(x) for x in merged]

        return publish_ack, ping_request

def wifi_dut_marker(IEEE802_11W=0, memory_config=0, OpenMode=0, HiddenSSID=0, ca_cert=0 , ssl=0):
    """
        Common method to generate wifi_dut marker for pytest.mark.config decorator.
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072},
                          "ble": {"count": 1, "stack_len": 3072}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT | OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | ssl,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | HiddenSSID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | IEEE802_11W | memory_config
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "ca_cert": ca_cert,
    }
    return pytest.mark.config("wifi_dut", wifi=config)

@pytest.mark.skip(reason="Skipping test_wifi_sdk_mqtt_subs_ble_dual_conn_c778114")
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
def test_wifi_sdk_mqtt_subs_ble_dual_conn_c778114(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, ble_client,
        ble_dut, utf_constants, mqtt_client, mqtt_server):
    """DUT is connected as a dual role with a connection interval of 45ms and 250ms and connect to the MQTT server over
    TCP and subscribe to the topic with QoS 1, publish data on the subscribed topic, and then disconnect """

    ble_obj=None
    try:
        test_name = request.node.name
        # assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic = 'weather'
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        topic_address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=topic_address1, size=len(topic), write_content=topic)

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=test_name, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=1)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.master_connection()
        ble_obj.slave_connection()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.mqtt_connection()
        wifi_obj.subscribe_and_publish(qos=1)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)

        wifi_dut.interfaces.wifi.memory_free(address2)
        wifi_dut.interfaces.wifi.memory_free(topic_address1)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()
        # ble_clients[0].interfaces.bluetooth.close()
        # ble_clients[1].interfaces.bluetooth.close()


@pytest.mark.run
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
@wifi_dut_marker()
def test_wifi_sdk_mqtt_subs_ble_slave_conn_c778115(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, ble_client,
    ble_dut, utf_constants, mqtt_client, mqtt_server):
    """QOS1: Subscribe to MQTT server with different topic lengths(62, 100,122,201) and pub max data of 1000 bytes over
    subs topic while DUT is connected as a peripheral along with BLE Tx data tranfer DLE """

    ble_obj=None
    try:
        test_name = request.node.name
        # assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic = 'weather'
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        topic_address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=topic_address1, size=len(topic), write_content=topic)

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=1)

        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Clearing any stale remote BLE device record before slave connection")
        try:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        except Exception as ble_reset_ex:
            logger().warning(f"Remote BLE pre-clean skipped due to error: {ble_reset_ex}")

        try:
            pre_slave_state = wifi_dut.interfaces.wifi.ble_get_device_state()
            logger().info(f"DUT BLE state before slave connection attempt: {pre_slave_state}")
        except Exception as ble_state_ex:
            logger().warning(f"BLE state read before slave connection failed: {ble_state_ex}")
        ble_obj.slave_connection()
        logger().info("Updating BLE connection interval to 80 ms for DUT peripheral connection")
        ble_client.interfaces.bluetooth.hci_tool_manager.update_conn(
            dev_addr=ble_obj.ble_dut_address,
            min_conn_interval=int(80 / 1.25),
            max_conn_interval=int(80 / 1.25),
            conn_latency=0,
            supervision_timeout=3200,
        )
        time.sleep(5)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # DUT side: use paho_mqtt command handlers
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        server_ip = mqtt_server.interfaces.mqtt.hostname_or_ip_address
        server_port = mqtt_server.interfaces.mqtt.port

        wifi_dut.interfaces.mqtt.paho_mqtt_set_advanced_configuration_command_handler(
            last_will_qos=Si91xMqttQos.QOS1,
            is_will_enabled=0,
            last_will_retain=0,
        )
        wifi_dut.interfaces.mqtt.paho_mqtt_client_connect_to_server_command_handler(
            broker_address=server_ip,
            broker_port=server_port,
            client_id="Si91x_mqtt_client",
            keep_alive_time_ms=60,
        )

        # Host side remains the regular mqtt client wrapper.
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(
            topic=topic,
            qos_level=Si91xMqttQos.QOS1,
        )
        message_buffer = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=message_buffer, size=len(message), write_content=message)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_publish_command_handler(
            topic=topic,
            qos_level=Si91xMqttQos.QOS1,
            msg_payload_len=len(message),
            use_higher_data_len=1,
            data_buffer=message_buffer,
        )
        wifi_dut.interfaces.wifi.memory_free(message_buffer)
        time.sleep(3)

        topic_length = [62, 100, 122, 201]
        for length in topic_length:
            topic = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))
            mqtt_client.interfaces.mqtt.received_messages.clear()
            logger().info(f" Topic Length : {length} bytes")
            logger().info("**************** DUT subscribes to the topic ****************")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
            wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(
                topic=topic,
                qos_level=Si91xMqttQos.QOS1,
            )

            time.sleep(3)

            logger().info("Host publishes message over the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_publish(
                topic=topic,
                payload=message,
                qos=Si91xMqttQos.QOS1,
            )
            time.sleep(3)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) == 1:
                    break
            assert len(msgs) == 1, "No message is received by mqtt-client"
            assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                        "message received is wrong"
            assert msgs[0].qos == Si91xMqttQos.QOS1, "mqtt-client received message with wrong QOS. expected is QOS1"
            logger().info("DUT unsubscribes to the topic")
            wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic)
            time.sleep(2)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic)
        time.sleep(1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception as cleanup_ex:
                logger().warning(f"BLE cleanup skipped due to error: {cleanup_ex}")
        # ble_clients[0].interfaces.bluetooth.close()


@pytest.mark.run
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
@wifi_dut_marker()
@pytest.mark.parametrize("keep_alive_time,idle_time", [(0, 120)])
def test_wifi_sdk_mqtt_keep_alive_ble_diff_conn_c778116(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, ble_client,
        ble_dut, utf_constants,  mqtt_client, mqtt_server, keep_alive_time, idle_time):
    """Verify MQTT keep alive functionality when keep alive set to 0 when BLE in peripheral conn with different
    conn int(30ms,125ms,250ms, 500ms) and adv int (500ms) """

    ble_obj=None
    try:
        test_name = request.node.name
        # assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic = 'weather'
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))
        capture_filename = request.node.name
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        topic_address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=topic_address1, size=len(topic), write_content=topic)

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=1)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.multiple_ble_conn_intervals()
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # DUT side: use paho_mqtt command handlers and keep test keep-alive parameter intact.
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        server_ip = mqtt_server.interfaces.mqtt.hostname_or_ip_address
        server_port = mqtt_server.interfaces.mqtt.port

        wifi_dut.interfaces.mqtt.paho_mqtt_set_advanced_configuration_command_handler(
            last_will_qos=Si91xMqttQos.QOS1,
            is_will_enabled=0,
            last_will_retain=0,
        )
        wifi_dut.interfaces.mqtt.paho_mqtt_client_connect_to_server_command_handler(
            broker_address=server_ip,
            broker_port=server_port,
            client_id="Si91x_mqtt_client",
            keep_alive_time_ms=keep_alive_time,
        )

        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(
            topic=topic,
            qos_level=Si91xMqttQos.QOS1,
        )
        time.sleep(3)

        message_buffer = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=message_buffer, size=len(message), write_content=message)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_publish_command_handler(
            topic=topic,
            qos_level=Si91xMqttQos.QOS1,
            msg_payload_len=len(message),
            use_higher_data_len=1,
            data_buffer=message_buffer,
        )
        wifi_dut.interfaces.wifi.memory_free(message_buffer)
        time.sleep(3)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS0"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"

        logger().info(f"Wait for {idle_time} seconds")
        time.sleep(idle_time)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)
        
        # Keep-alive validation: core test ensures keep_alive_time_ms=0 is passed to DUT connect.
        # This effectively disables MQTT keep-alive at the protocol level.
        logger().info("MQTT keep-alive is disabled by passing keep_alive_time_ms=0 to DUT")

        wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic)
        time.sleep(1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()

        publish_ack, ping_request = wifi_obj.mqtt_keep_alive_check(
            wifi_obj.dut_addr['dut_mac_address'],
            capture_filename,
            keep_alive_time_sec=keep_alive_time,
        )
        if len(ping_request) >= 1:
            assert not len(ping_request), "MQTT keep alive packets capture even though keep alive is disable"
        else :
            logger().info("....MQTT keep alive packets not observed when we disable keep alive....")

        wifi_dut.interfaces.wifi.memory_free(address2)
        wifi_dut.interfaces.wifi.memory_free(topic_address1)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception as cleanup_ex:
                logger().warning(f"BLE cleanup skipped due to error: {cleanup_ex}")
        # ble_clients[0].interfaces.bluetooth.close()


@pytest.mark.run
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
@wifi_dut_marker()
def test_wifi_sdk_mqtt_retain_bit_ble_provisioning_c778117(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, ble_client,
        ble_dut, utf_constants, mqtt_client, mqtt_server):
    """Verify BLE provisioning and MQTT publish functionality by enabling retain bit set to True"""

    ble_obj=None
    try:
        test_name = request.node.name


        topic = 'weather'
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        topic_address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=topic_address1, size=len(topic), write_content=topic)

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=1)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.slave_connection()
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # DUT side: use paho_mqtt command handlers and keep retain behavior enabled for this test.
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        server_ip = mqtt_server.interfaces.mqtt.hostname_or_ip_address
        server_port = mqtt_server.interfaces.mqtt.port

        wifi_dut.interfaces.mqtt.paho_mqtt_set_advanced_configuration_command_handler(
            last_will_qos=Si91xMqttQos.QOS1,
            is_will_enabled=0,
            last_will_retain=0,
        )
        wifi_dut.interfaces.mqtt.paho_mqtt_client_connect_to_server_command_handler(
            broker_address=server_ip,
            broker_port=server_port,
            client_id="Si91x_mqtt_client",
        )

        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(
            topic=topic,
            qos_level=Si91xMqttQos.QOS1,
        )
        time.sleep(3)

        message_buffer = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=message_buffer, size=len(message), write_content=message)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_publish_command_handler(
            topic=topic,
            qos_level=Si91xMqttQos.QOS1,
            is_msg_retained=1,
            msg_payload_len=len(message),
            use_higher_data_len=1,
            data_buffer=message_buffer,
        )
        wifi_dut.interfaces.wifi.memory_free(message_buffer)
        time.sleep(3)

        # ===== RETAIN VERIFICATION START =====
        logger().info("Going to validate retained message behavior on host client")
        logger().info("Step 1: unsubscribe host client from topic to create a late subscriber scenario")
        mqtt_client.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(1)
        logger().info("Step 2: clear previously received host messages before retained validation")
        mqtt_client.interfaces.mqtt.received_messages.clear()
        logger().info("Step 3: resubscribe host client to topic and wait for retained delivery")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        retained_msg = None
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            for msg in reversed(msgs):
                if getattr(msg, "topic", None) == topic:
                    retained_msg = msg
                    logger().info("Retained message received on host subscriber; validating topic, payload, and retain flag")
                    break
            if retained_msg is not None:
                break

        assert retained_msg is not None, "Retained message was not delivered to late host subscriber"
        payload = retained_msg.payload
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode(errors="ignore")
        payload = str(payload).strip("\r\n\0 ")
        assert payload == message, "Retained payload mismatch on host subscriber"
        assert bool(getattr(retained_msg, "retain", False)), "Received message retain flag is not set"
        logger().info("Retain validation completed successfully because host received retained message with expected payload and retain flag")
        # ===== RETAIN VERIFICATION END =====

        logger().info(".....Unsubscribe from the topic.....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic)
        time.sleep(1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
        time.sleep(3)

        wifi_dut.interfaces.wifi.memory_free(address2)
        wifi_dut.interfaces.wifi.memory_free(topic_address1)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception as cleanup_ex:
                logger().warning(f"BLE cleanup skipped due to error: {cleanup_ex}")


@pytest.mark.run
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
@wifi_dut_marker(memory_config= Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode, 
                 ssl= Si91xTCPIPFeatureBitMap.SSL , 
                 ca_cert= ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
def test_wifi_sdk_mqtt_ssl_ble_master_c778118(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, ble_client,
        ble_dut, utf_constants, mqtt_client, mqtt_server):
    """DUT is connected as a central with a conn int of 80ms and Connect to the MQTT server over TLS,Pub the msg on the
    topic with Qos1, and then disconnect(BLE activity in loop for multiple iteration"""

    ble_obj=None
    ca_cert_address = None
    try:
        test_name = request.node.name
        # assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic = 'weather'
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        topic_address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=topic_address1, size=len(topic), write_content=topic)

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=1)

        ble_obj.start()
        ble_obj.wait_for_exit()
######################### additional pre-clean steps to ensure no stale BLE state interferes with master connection #########################
        logger().info("Clearing any stale remote BLE device record before master connection")
        try:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        except Exception as ble_reset_ex:
            logger().warning(f"Remote BLE pre-clean skipped due to error: {ble_reset_ex}")

        try:
            pre_master_state = wifi_dut.interfaces.wifi.ble_get_device_state()
            logger().info(f"DUT BLE state before master connection attempt: {pre_master_state}")
        except Exception as ble_state_ex:
            logger().warning(f"BLE state read before master connection failed: {ble_state_ex}")
########################################################################################################################################
        ble_obj.master_connection()
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # DUT side: use paho_mqtt command handlers with TLS.
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        server_ip = mqtt_server.interfaces.mqtt.hostname_or_ip_address
        server_port = mqtt_server.interfaces.mqtt.port
        ca_cert_name = "ca-chain.cert.pem"

        logger().info("Loading CA certificate into DUT memory for TLS MQTT connection")
        cert_file = str(get_tls_certificate_dir().joinpath(ca_cert_name))
        with open(cert_file) as f:
            cert_contents = f.read()
        cert_size = len(cert_contents)

        cert_buffer_size = (512 * int(cert_size / 512)) + 512
        ca_cert_address = wifi_dut.interfaces.wifi.allocate_memory(size=cert_buffer_size)
        wifi_dut.interfaces.wifi.load_memory(
            ca_cert_address,
            size=cert_size,
            write_content=cert_contents,
        )

        wifi_dut.interfaces.mqtt.paho_mqtt_set_advanced_configuration_command_handler(
            ca_cert=ca_cert_address,
            ca_cert_length=cert_size,
            last_will_qos=Si91xMqttQos.QOS1,
            is_will_enabled=1,
            last_will_retain=1,
        )
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.mqtt.paho_mqtt_client_connect_to_server_command_handler(
            broker_address=server_ip,
            broker_port=server_port,
            client_id="Si91x_mqtt_client",
            enable_ssl=1,
        )
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

        # Host side remains the regular mqtt client wrapper.
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(
            topic=topic,
            qos_level=Si91xMqttQos.QOS1,
        )
        time.sleep(3)

        message_buffer = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=message_buffer, size=len(message), write_content=message)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_publish_command_handler(
            topic=topic,
            qos_level=Si91xMqttQos.QOS1,
            msg_payload_len=len(message),
            use_higher_data_len=1,
            data_buffer=message_buffer,
        )
        wifi_dut.interfaces.wifi.memory_free(message_buffer)
        time.sleep(3)

        logger().info(".....Unsubscribe from the topic.....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic)
        time.sleep(1)
        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
        time.sleep(3)

        wifi_dut.interfaces.wifi.memory_free(address2)
        wifi_dut.interfaces.wifi.memory_free(topic_address1)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ca_cert_address is not None:
            try:
                wifi_dut.interfaces.wifi.memory_free(ca_cert_address)
            except Exception as cert_free_ex:
                logger().warning(f"CA cert memory cleanup skipped due to error: {cert_free_ex}")
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception as cleanup_ex:
                logger().warning(f"BLE cleanup skipped due to error: {cleanup_ex}")
        # ble_clients[0].interfaces.bluetooth.close()


@pytest.mark.run
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@wifi_dut_marker(memory_config= Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode, 
                 ssl= Si91xTCPIPFeatureBitMap.SSL , 
                 ca_cert= ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
def test_wifi_sdk_mqtt_ssl_diff_username_ble_master_c778119(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, ble_client,
        ble_dut, utf_constants, mqtt_client, mqtt_server):
    """QOS1:Sub to MQTT server with SSL conn with diff Username lengths(62,100,121) and pub max data of 1000bytes on
    sub topic while DUT is connected as a central with BLE Rx notification with DLE enabled """

    ble_obj=None
    ca_cert_address = None
    try:
        test_name = request.node.name
        # assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic = 'weather'
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))

        username_length = [
            "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyus",
            "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewit",
            "myusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyusernamewithdifferentlengthmyuse"]

        password = ["FROM_TEST_1", "FROM_TEST_2", "FROM_TEST_3"]
        message_length = [1, 10, 100, 512, 1000, 1351]

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        topic_address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=topic_address1, size=len(topic), write_content=topic)

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=1)

        ble_obj.start()
        ble_obj.wait_for_exit()
############################# additional pre-clean steps to ensure no stale BLE state interferes with master connection #########################
        logger().info("Clearing any stale remote BLE device record before master connection")
        try:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        except Exception as ble_reset_ex:
            logger().warning(f"Remote BLE pre-clean skipped due to error: {ble_reset_ex}")

        try:
            pre_master_state = wifi_dut.interfaces.wifi.ble_get_device_state()
            logger().info(f"DUT BLE state before master connection attempt: {pre_master_state}")
        except Exception as ble_state_ex:
            logger().warning(f"BLE state read before master connection failed: {ble_state_ex}")
##########################################
        ble_obj.master_connection()
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        server_ip = mqtt_server.interfaces.mqtt.hostname_or_ip_address
        server_port = mqtt_server.interfaces.mqtt.port

        logger().info("Loading CA certificate into DUT memory for TLS MQTT username validation")
        cert_file = str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem"))
        with open(cert_file) as f:
            cert_contents = f.read()
        cert_size = len(cert_contents)
        cert_buffer_size = (512 * int(cert_size / 512)) + 512
        ca_cert_address = wifi_dut.interfaces.wifi.allocate_memory(size=cert_buffer_size)
        wifi_dut.interfaces.wifi.load_memory(ca_cert_address, size=cert_size, write_content=cert_contents)

        for length in range(len(username_length)):
            logger().info(
                f"==================== iteration for username length: {len(username_length[length])} ====================")

            wifi_dut.interfaces.mqtt.paho_mqtt_set_advanced_configuration_command_handler(
                ca_cert=ca_cert_address,
                ca_cert_length=cert_size,
                last_will_qos=Si91xMqttQos.QOS1,
                is_will_enabled=0,
                last_will_retain=0,
            )

            logger().info("Both DUT and third-party mqtt client connects to MQTT server")
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            wifi_dut.interfaces.mqtt.paho_mqtt_client_connect_to_server_command_handler(
                broker_address=server_ip,
                broker_port=server_port,
                client_id="Si91x_mqtt_client",
                username=username_length[length],
                password=password[length],
                enable_ssl=1,
            )
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            time.sleep(5)

            logger().info("**************** MQTT_client subscribes to the topic ****************")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

            logger().info("**************** DUT subscribes to the topic ****************")
            wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(
                topic=topic,
                qos_level=Si91xMqttQos.QOS1,
            )

            time.sleep(3)
            mqtt_client.interfaces.mqtt.received_messages.clear()
            for msg_length in message_length:
                logger().info(
                    f"==================== Iteration for Message length: {len(username_length[length])} ====================")
                message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=msg_length))
                logger().info("********** DUT publishes message over the topic ****************")
                message_buffer = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
                wifi_dut.interfaces.wifi.load_memory(address=message_buffer, size=len(message), write_content=message)
                wifi_dut.interfaces.mqtt.paho_mqtt_client_publish_command_handler(
                    topic=topic,
                    qos_level=Si91xMqttQos.QOS1,
                    msg_payload_len=len(message),
                    use_higher_data_len=1,
                    data_buffer=message_buffer,
                )
                wifi_dut.interfaces.wifi.memory_free(message_buffer)

                sw = Stopwatch()
                matched_msg = None
                while sw.elapsed_sec < 10:
                    time.sleep(0.1)
                    msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                    for received_msg in reversed(msgs):
                        payload = received_msg.payload
                        if isinstance(payload, (bytes, bytearray)):
                            payload = payload.decode(errors="ignore")
                        if (
                            getattr(received_msg, "topic", None) == topic
                            and str(payload).strip("\r\n\0 ") == message
                            and getattr(received_msg, "qos", None) == Si91xMqttQos.QOS1
                        ):
                            matched_msg = received_msg
                            break
                    if matched_msg is not None:
                        break

                assert matched_msg is not None, (
                    f"No matched QOS1 message received for username length {len(username_length[length])} "
                    f"and payload length {msg_length}"
                )

            logger().info("************ DUT unsubscribes to the topic ******************")
            wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic)
            time.sleep(2)

            logger().info("************ Disconnecting from MQTT Server ******************")
            wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
            time.sleep(2)

        logger().info("************ Stop the sniffer **************")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.memory_free(address2)
        wifi_dut.interfaces.wifi.memory_free(topic_address1)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ca_cert_address is not None:
            try:
                wifi_dut.interfaces.wifi.memory_free(ca_cert_address)
            except Exception as cert_free_ex:
                logger().warning(f"CA cert memory cleanup skipped due to error: {cert_free_ex}")
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception as cleanup_ex:
                logger().warning(f"BLE cleanup skipped due to error: {cleanup_ex}")
        # ble_clients[0].interfaces.bluetooth.close()

@pytest.mark.run
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
@wifi_dut_marker(memory_config= Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
                 ssl= Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert= ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
def test_wifi_sdk_mqtt_ssl_single_level_card_ble_slave_c778120(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, ble_client,
        ble_dut, utf_constants,  mqtt_client, mqtt_server):
    """DUT is connected as a peripheral with a connection interval of 80ms along with BLE Tx notification(100bytes) and
    verify DUT functionality with MQTT subscription using Single Level wild card character(+) in the topic name """

    ble_obj=None
    ca_cert_address = None
    topic = None
    host_topic_subscribed = False
    host_mqtt_connected = False
    dut_topic_subscribed = False
    dut_mqtt_connected = False
    ble_service_created = False
    char_path = None
    try:
        test_name = request.node.name
        # assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic = "mytesttopic/+/mytesttopic"
        multiple_topic = ["mytesttopic/sensor/mytesttopic", "mytesttopic/automation/mytesttopic",
                          "mytesttopic/siliconlabs/mytesttopic"]
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))
        gatt_index = 1

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        topic_address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=topic_address1, size=len(topic), write_content=topic)

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=1)

        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Clearing stale BLE device/service state before slave connection")
        try:
            wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        except Exception as stale_service_ex:
            logger().warning(f"Initial BLE service cleanup skipped due to error: {stale_service_ex}")
        try:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        except Exception as stale_device_ex:
            logger().warning(f"Initial BLE device cleanup skipped due to error: {stale_device_ex}")
        logger().info("Creating custom GATT service and notify characteristic in DUT for BLE Tx validation")
        wifi_dut.interfaces.wifi.ble_add_service(uid=hex(0xAABB))
        ble_service_created = True
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1,
            service_handler_num=gatt_index,
            value_handler_num=gatt_index + 1,
        )
        wifi_dut.interfaces.wifi.ble_add_char_val_att(
            uid=0x1AA1,
            value_handler_num=gatt_index + 1,
        )
        ble_obj.slave_connection()
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        server_ip = mqtt_server.interfaces.mqtt.hostname_or_ip_address
        server_port = mqtt_server.interfaces.mqtt.port

        logger().info("Loading CA certificate into DUT memory for TLS MQTT wildcard validation")
        cert_file = str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem"))
        with open(cert_file) as f:
            cert_contents = f.read()
        cert_size = len(cert_contents)
        cert_buffer_size = (512 * int(cert_size / 512)) + 512
        ca_cert_address = wifi_dut.interfaces.wifi.allocate_memory(size=cert_buffer_size)
        wifi_dut.interfaces.wifi.load_memory(ca_cert_address, size=cert_size, write_content=cert_contents)

        wifi_dut.interfaces.mqtt.paho_mqtt_set_advanced_configuration_command_handler(
            ca_cert=ca_cert_address,
            ca_cert_length=cert_size,
            last_will_qos=Si91xMqttQos.QOS1,
            is_will_enabled=0,
            last_will_retain=0,
        )

        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.mqtt.paho_mqtt_client_connect_to_server_command_handler(
            broker_address=server_ip,
            broker_port=server_port,
            client_id="Si91x_mqtt_client",
            enable_ssl=1,
        )
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        host_mqtt_connected = True
        dut_mqtt_connected = True
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        host_topic_subscribed = True

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(
            topic=topic,
            qos_level=Si91xMqttQos.QOS1,
        )
        dut_topic_subscribed = True
        time.sleep(3)

        notify_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        logger().info("Resolving remote notify characteristic for DUT BLE Tx validation")
        char_path = sl_collections.service_discovery_on_remote(
            ble_client,
            service_uid=service_uid,
            char_uid=char_uid,
        )
        logger().info(f"Resolved notify characteristic path: {char_path}")
        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=char_path,
            char_uid=char_uid,
        )
        wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=ble_obj.ble_client_address,
            buffer_mode=1,
            buffer_count=2,
        )
        time.sleep(2)
        logger().info("DUT peripheral sends BLE Tx notification of 100 bytes")
        notify_data_address = wifi_dut.interfaces.wifi.allocate_memory(size=len(notify_data) + 1)
        wifi_dut.interfaces.wifi.load_memory(
            address=notify_data_address,
            size=len(notify_data),
            write_content=notify_data,
        )
        try:
            wifi_dut.interfaces.wifi.ble_notify_custom_value(
                ble_obj.ble_client_address,
                data=notify_data,
                data_address=notify_data_address,
            )
        finally:
            wifi_dut.interfaces.wifi.memory_free(notify_data_address)
        time.sleep(10)
        notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        assert len(notifications) > 0, "received data is empty"
        logger().info(f"notifications received on remote :{notifications}")
        assert notifications[0] in notify_data, "BLE notification payload mismatch"
        ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        time.sleep(3)

        count = 0
        logger().info("**************** DUT publishes message over multiple topics *****************")
        for length in multiple_topic:
            wifi_dut.interfaces.mqtt.paho_mqtt_client_publish_command_handler(
                topic=length,
                qos_level=Si91xMqttQos.QOS1,
                msg_payload_len=len(message),
                use_higher_data_len=1,
                data_buffer=address2,
                timeout=20,
            )
            time.sleep(2)
            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

            assert msgs[count].topic == multiple_topic[count], "No message received by mqtt-client on subscribed topic1"
            assert msgs[count].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
            assert msgs[
                       count].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                           "message received is wrong"
            count += 1

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic....")
        mqtt_client.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        host_topic_subscribed = False

        logger().info(".....Unsubscribe from the topic.....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic)
        dut_topic_subscribed = False
        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
        dut_mqtt_connected = False
        if getattr(mqtt_client.interfaces.mqtt, "client", None) is not None:
            mqtt_client.interfaces.mqtt.mqtt_client_close()
            host_mqtt_connected = False
        time.sleep(3)

        wifi_dut.interfaces.wifi.memory_free(address2)
        wifi_dut.interfaces.wifi.memory_free(topic_address1)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if topic is not None and host_topic_subscribed and getattr(mqtt_client.interfaces.mqtt, "client", None) is not None:
            try:
                mqtt_client.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
                host_topic_subscribed = False
            except Exception as host_unsub_ex:
                logger().warning(f"Host MQTT unsubscribe cleanup skipped due to error: {host_unsub_ex}")
        if host_mqtt_connected and getattr(mqtt_client.interfaces.mqtt, "client", None) is not None:
            try:
                mqtt_client.interfaces.mqtt.mqtt_client_close()
                host_mqtt_connected = False
            except Exception as host_disc_ex:
                logger().warning(f"Host MQTT disconnect cleanup skipped due to error: {host_disc_ex}")
        if hasattr(wifi_dut.interfaces, "mqtt"):
            if topic is not None and dut_topic_subscribed:
                dut_unsubscribed = False
                for unsubscribe_attempt in range(1, 6):
                    try:
                        wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic, timeout=60)
                        dut_topic_subscribed = False
                        dut_unsubscribed = True
                        break
                    except Exception as dut_unsub_ex:
                        logger().warning(
                            f"DUT MQTT unsubscribe cleanup attempt {unsubscribe_attempt}/5 failed: {dut_unsub_ex}"
                        )
                        time.sleep(2)
                if not dut_unsubscribed:
                    logger().warning("DUT MQTT unsubscribe cleanup skipped after 5 attempts")
            if dut_mqtt_connected:
                dut_disconnected = False
                for disconnect_attempt in range(1, 6):
                    try:
                        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler(timeout=60)
                        dut_mqtt_connected = False
                        dut_disconnected = True
                        break
                    except Exception as dut_disc_ex:
                        logger().warning(
                            f"DUT MQTT disconnect cleanup attempt {disconnect_attempt}/5 failed: {dut_disc_ex}"
                        )
                        time.sleep(2)
                if not dut_disconnected:
                    logger().warning("DUT MQTT disconnect cleanup skipped after 5 attempts")
        if ca_cert_address is not None:
            try:
                wifi_dut.interfaces.wifi.memory_free(ca_cert_address)
                ca_cert_address = None
            except Exception as cert_free_ex:
                logger().warning(f"CA cert memory cleanup skipped due to error: {cert_free_ex}")
        if ble_obj is not None:
            if ble_service_created:
                try:
                    wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
                    ble_service_created = False
                except Exception as service_remove_ex:
                    logger().warning(f"BLE service cleanup skipped due to error: {service_remove_ex}")
            try:
                ble_obj.ble_cleanup()
            except Exception as cleanup_ex:
                logger().warning(f"BLE cleanup skipped due to error: {cleanup_ex}")
        # ble_clients[0].interfaces.bluetooth.close()

@pytest.mark.run
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
@wifi_dut_marker(memory_config= Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
                 ssl= Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert= ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
def test_wifi_sdk_mqtt_ssl_single_multiple_level_card_ble_slave_c778121(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, ble_client,
        ble_dut, utf_constants, mqtt_client, mqtt_server):
    """Verify DUT functionality by subscribing to an MQTT topic using both single-level (+) and multi-level (#)
    wildcards, and publish the data while transmitting 240 bytes over BLE with DLE enabled """

    ble_obj=None
    ca_cert_address = None
    topic = None
    host_topic_subscribed = False
    host_mqtt_connected = False
    dut_topic_subscribed = False
    dut_mqtt_connected = False
    ble_service_created = False
    try:
        test_name = request.node.name
        # assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic = "patch/+/properties/desired/#"
        multiple_topic = ["patch/iothub/properties/desired/sensor", "patch/substation/properties/desired/automation",
                          "patch/workspace/properties/desired/siliconlabs"]
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))
        gatt_index = 1

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        topic_address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=topic_address1, size=len(topic), write_content=topic)

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=1)

        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Clearing stale BLE device/service state before slave connection")
        try:
            wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        except Exception as stale_service_ex:
            logger().warning(f"Initial BLE service cleanup skipped due to error: {stale_service_ex}")
        try:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        except Exception as stale_device_ex:
            logger().warning(f"Initial BLE device cleanup skipped due to error: {stale_device_ex}")
        logger().info("Creating custom GATT service and notify characteristic in DUT for BLE Tx validation")
        wifi_dut.interfaces.wifi.ble_add_service(uid=hex(0xAABB))
        ble_service_created = True
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1,
            service_handler_num=gatt_index,
            value_handler_num=gatt_index + 1,
        )
        wifi_dut.interfaces.wifi.ble_add_char_val_att(
            uid=0x1AA1,
            value_handler_num=gatt_index + 1,
        )
        ble_obj.slave_connection()
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        server_ip = mqtt_server.interfaces.mqtt.hostname_or_ip_address
        server_port = mqtt_server.interfaces.mqtt.port

        logger().info("Loading CA certificate into DUT memory for TLS MQTT wildcard validation")
        cert_file = str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem"))
        with open(cert_file) as f:
            cert_contents = f.read()
        cert_size = len(cert_contents)
        cert_buffer_size = (512 * int(cert_size / 512)) + 512
        ca_cert_address = wifi_dut.interfaces.wifi.allocate_memory(size=cert_buffer_size)
        wifi_dut.interfaces.wifi.load_memory(ca_cert_address, size=cert_size, write_content=cert_contents)

        wifi_dut.interfaces.mqtt.paho_mqtt_set_advanced_configuration_command_handler(
            ca_cert=ca_cert_address,
            ca_cert_length=cert_size,
            last_will_qos=Si91xMqttQos.QOS1,
            is_will_enabled=0,
            last_will_retain=0,
        )

        logger().info("Both DUT and third-party mqtt client connects to MQTT server")
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.mqtt.paho_mqtt_client_connect_to_server_command_handler(
            broker_address=server_ip,
            broker_port=server_port,
            client_id="Si91x_mqtt_client",
            enable_ssl=1,
        )
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        host_mqtt_connected = True
        dut_mqtt_connected = True
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        host_topic_subscribed = True

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(
            topic=topic,
            qos_level=Si91xMqttQos.QOS1,
        )
        dut_topic_subscribed = True
        time.sleep(3)

        notify_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        logger().info("Resolving remote notify characteristic for DUT BLE Tx validation")
        char_path = sl_collections.service_discovery_on_remote(
            ble_client,
            service_uid=service_uid,
            char_uid=char_uid,
        )
        logger().info(f"Resolved notify characteristic path: {char_path}")
        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=char_path,
            char_uid=char_uid,
        )
        wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=ble_obj.ble_client_address,
            buffer_mode=1,
            buffer_count=2,
        )
        time.sleep(2)
        logger().info("DUT peripheral sends BLE Tx notification of 240 bytes")
        notify_data_address = wifi_dut.interfaces.wifi.allocate_memory(size=len(notify_data) + 1)
        wifi_dut.interfaces.wifi.load_memory(
            address=notify_data_address,
            size=len(notify_data),
            write_content=notify_data,
        )
        try:
            wifi_dut.interfaces.wifi.ble_notify_custom_value(
                ble_obj.ble_client_address,
                data=notify_data,
                data_address=notify_data_address,
            )
        finally:
            wifi_dut.interfaces.wifi.memory_free(notify_data_address)
        time.sleep(10)
        notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        assert len(notifications) > 0, "received data is empty"
        logger().info(f"notifications received on remote :{notifications}")
        assert notifications[0] in notify_data, "BLE notification payload mismatch"
        ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        time.sleep(3)

        count = 0
        logger().info("**************** DUT publishes message over multiple topics *****************")
        for length in multiple_topic:
            wifi_dut.interfaces.mqtt.paho_mqtt_client_publish_command_handler(
                topic=length,
                qos_level=Si91xMqttQos.QOS1,
                msg_payload_len=len(message),
                use_higher_data_len=1,
                data_buffer=address2,
                timeout=20,
            )
            time.sleep(2)
            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

            assert msgs[count].topic == multiple_topic[count], "No message received by mqtt-client on subscribed topic1"
            assert msgs[count].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
            assert msgs[
                       count].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                           "message received is wrong"
            count += 1

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic....")
        mqtt_client.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        host_topic_subscribed = False

        logger().info(".....Unsubscribe from the topic.....")
        wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic)
        dut_topic_subscribed = False
        wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
        dut_mqtt_connected = False
        if getattr(mqtt_client.interfaces.mqtt, "client", None) is not None:
            mqtt_client.interfaces.mqtt.mqtt_client_close()
            host_mqtt_connected = False
        time.sleep(3)

        wifi_dut.interfaces.wifi.memory_free(address2)
        wifi_dut.interfaces.wifi.memory_free(topic_address1)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if topic is not None and host_topic_subscribed and getattr(mqtt_client.interfaces.mqtt, "client", None) is not None:
            try:
                mqtt_client.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
                host_topic_subscribed = False
            except Exception as host_unsub_ex:
                logger().warning(f"Host MQTT unsubscribe cleanup skipped due to error: {host_unsub_ex}")
        if host_mqtt_connected and getattr(mqtt_client.interfaces.mqtt, "client", None) is not None:
            try:
                mqtt_client.interfaces.mqtt.mqtt_client_close()
                host_mqtt_connected = False
            except Exception as host_disc_ex:
                logger().warning(f"Host MQTT disconnect cleanup skipped due to error: {host_disc_ex}")
        if hasattr(wifi_dut.interfaces, "mqtt"):
            if topic is not None and dut_topic_subscribed:
                try:
                    wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic)
                    dut_topic_subscribed = False
                except Exception as dut_unsub_ex:
                    logger().warning(f"DUT MQTT unsubscribe cleanup skipped due to error: {dut_unsub_ex}")
            if dut_mqtt_connected:
                try:
                    wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
                    dut_mqtt_connected = False
                except Exception as dut_disc_ex:
                    logger().warning(f"DUT MQTT disconnect cleanup skipped due to error: {dut_disc_ex}")
        if ca_cert_address is not None:
            try:
                wifi_dut.interfaces.wifi.memory_free(ca_cert_address)
                ca_cert_address = None
            except Exception as cert_free_ex:
                logger().warning(f"CA cert memory cleanup skipped due to error: {cert_free_ex}")
        if ble_obj is not None:
            if ble_service_created:
                try:
                    wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
                    ble_service_created = False
                except Exception as service_remove_ex:
                    logger().warning(f"BLE service cleanup skipped due to error: {service_remove_ex}")
            try:
                ble_obj.ble_cleanup()
            except Exception as cleanup_ex:
                logger().warning(f"BLE cleanup skipped due to error: {cleanup_ex}")
        # ble_clients[0].interfaces.bluetooth.close()


@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
def test_wifi_sdk_mqtt_ssl_rejoin_ble_dual_role_c778122(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, ble_client,
        ble_dut, utf_constants, ble_clients, mqtt_client, mqtt_server, switch):
    """QOS1:check whether DUT is able to reconnect MQTT and subscribe with 2 topics and publish after rejoin process
    when BLE Acts as DUAL Role (Both Master(100ms) and Slave(30ms"""

    ble_obj=None
    try:
        test_name = request.node.name
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic = 'weather'
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        topic_address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=topic_address1, size=len(topic), write_content=topic)

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=1)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.slave_connection()
        ble_obj.master_connection()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.mqtt_connection_ssl()
        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=1)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=1)
        time.sleep(3)

        logger().info("Turning off the AP")
        switch.interfaces.pdu_switch.turn_off(delay=20)

        logger().info("Successfully powered off AP")
        time.sleep(60)
        wifi_obj.rejoin_async_event()
        logger().info("Again turning on the AP")
        switch.interfaces.pdu_switch.turn_on(delay=100)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)

        logger().info(".....Unsubscribe from the topic.....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        time.sleep(3)

        wifi_dut.interfaces.wifi.memory_free(address2)
        wifi_dut.interfaces.wifi.memory_free(topic_address1)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()
        ble_clients[0].interfaces.bluetooth.close()

@pytest.mark.run
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
@wifi_dut_marker(memory_config= Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
                 ssl= Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert= ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
def test_wifi_sdk_mqtt_ssl_ble_slave_long_run_c778123(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, ble_client,
        ble_dut, utf_constants, mqtt_client, mqtt_server):
    """Connect BLE as Slave mode and run 20 bytes of TX data while subscribing to MQTT server with qos1 and
    SSL connection, then repeat scan/connect/ipconfig/subscribe/publish/disconnect in a configured iteration loop."""

    ble_obj=None
    ca_cert_address = None
    topic = None
    host_topic_subscribed = False
    host_mqtt_connected = False
    dut_topic_subscribed = False
    dut_mqtt_connected = False
    ble_service_created = False
    try:
        test_name = request.node.name
        # assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic = 'weather'
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000))
        iteration_count = 10
        wifi_retry_count = 5
        wifi_disconnect_retry_count = 5
        mqtt_publish_retry_count = 5
        mqtt_unsubscribe_retry_count = 5
        mqtt_disconnect_retry_count = 5
        gatt_index = 1
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        topic_address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=topic_address1, size=len(topic), write_content=topic)

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, mqtt_server=mqtt_server, mqtt_client=mqtt_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, topic=topic,
                            message=message, retry_count=wifi_retry_count,
                            disconnect_retry_count=wifi_disconnect_retry_count)

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        server_ip = mqtt_server.interfaces.mqtt.hostname_or_ip_address
        server_port = mqtt_server.interfaces.mqtt.port

        logger().info("Loading CA certificate into DUT memory for TLS MQTT long-run validation")
        cert_file = str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem"))
        with open(cert_file) as f:
            cert_contents = f.read()
        cert_size = len(cert_contents)
        cert_buffer_size = (512 * int(cert_size / 512)) + 512
        ca_cert_address = wifi_dut.interfaces.wifi.allocate_memory(size=cert_buffer_size)
        wifi_dut.interfaces.wifi.load_memory(ca_cert_address, size=cert_size, write_content=cert_contents)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=0)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Clearing stale BLE device/service state before slave connection")
        try:
            wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        except Exception as stale_service_ex:
            logger().warning(f"Initial BLE service cleanup skipped due to error: {stale_service_ex}")
        try:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        except Exception as stale_device_ex:
            logger().warning(f"Initial BLE device cleanup skipped due to error: {stale_device_ex}")
        logger().info("Creating custom GATT service and notify characteristic in DUT for BLE Tx validation")
        wifi_dut.interfaces.wifi.ble_add_service(uid=hex(0xAABB))
        ble_service_created = True
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1,
            service_handler_num=gatt_index,
            value_handler_num=gatt_index + 1,
        )
        wifi_dut.interfaces.wifi.ble_add_char_val_att(
            uid=0x1AA1,
            value_handler_num=gatt_index + 1,
        )
        ble_obj.slave_connection()
        logger().info("Updating BLE connection interval to 80 ms for DUT peripheral connection")
        ble_client.interfaces.bluetooth.hci_tool_manager.update_conn(
            dev_addr=ble_obj.ble_dut_address,
            min_conn_interval=int(80 / 1.25),
            max_conn_interval=int(80 / 1.25),
            conn_latency=0,
            supervision_timeout=3200,
        )
        time.sleep(5)
        logger().info("Resolving remote notify characteristic for DUT BLE Tx validation")
        char_path = None
        char_props = None
        for discovery_attempt in range(1, 6):
            logger().info(f"GATT discovery attempt {discovery_attempt} for DUT BLE Tx validation")
            time.sleep(3)
            servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            logger().info(f"Resolved services: {servs}, characteristics: {chars}")
            if len(servs) == 0 or len(chars) == 0:
                time.sleep(3)
                continue

            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid,
                char_uid=char_uid,
            )
            logger().info(f"Resolved characteristic properties: {char_props}")
            if char_path and len(char_props) > 0:
                break
            time.sleep(3)

        assert char_path, "Notify characteristic path is empty after GATT discovery retries"
        logger().info(f"Resolved notify characteristic path: {char_path}")
        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=char_path,
            char_uid=char_uid,
        )
        wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=ble_obj.ble_client_address,
            buffer_mode=1,
            buffer_count=2,
        )
        time.sleep(2)
        initial_notification_count = len(ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid])

        for iteration in range(iteration_count):
            logger().info(f"***** Iteration {iteration + 1}/{iteration_count} *****")
            notify_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
            logger().info("DUT peripheral sends BLE Tx notification of 20 bytes")
            previous_notification_count = len(ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid])
            notify_data_address = wifi_dut.interfaces.wifi.allocate_memory(size=len(notify_data) + 1)
            wifi_dut.interfaces.wifi.load_memory(
                address=notify_data_address,
                size=len(notify_data),
                write_content=notify_data,
            )
            try:
                wifi_dut.interfaces.wifi.ble_notify_custom_value(
                    ble_obj.ble_client_address,
                    data=notify_data,
                    data_address=notify_data_address,
                )
            finally:
                wifi_dut.interfaces.wifi.memory_free(notify_data_address)
            time.sleep(10)
            notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
            assert len(notifications) > previous_notification_count, "received data is empty"
            logger().info(f"notifications received on remote :{notifications}")
            assert notifications[-1] in notify_data, "BLE notification payload mismatch"

            wifi_obj.start()
            wifi_obj.wait_for_exit()

            wifi_dut.interfaces.mqtt.paho_mqtt_set_advanced_configuration_command_handler(
                ca_cert=ca_cert_address,
                ca_cert_length=cert_size,
                last_will_qos=Si91xMqttQos.QOS1,
                is_will_enabled=0,
                last_will_retain=0,
            )

            logger().info("Both DUT and third-party mqtt client connects to MQTT server")
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            wifi_dut.interfaces.mqtt.paho_mqtt_client_connect_to_server_command_handler(
                broker_address=server_ip,
                broker_port=server_port,
                client_id="Si91x_mqtt_client",
                enable_ssl=1,
            )
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
            host_mqtt_connected = True
            dut_mqtt_connected = True
            time.sleep(5)

            logger().info("MQTT Client subscribes to the topic")
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
            host_topic_subscribed = True

            logger().info("DUT subscribes to the topic")
            wifi_dut.interfaces.mqtt.paho_mqtt_client_subscribe_command_handler(
                topic=topic,
                qos_level=Si91xMqttQos.QOS1,
            )
            dut_topic_subscribed = True
            time.sleep(3)

            logger().info("DUT publishes message over the topic")
            publish_error = None
            for publish_attempt in range(1, mqtt_publish_retry_count + 1):
                try:
                    wifi_dut.interfaces.mqtt.paho_mqtt_client_publish_command_handler(
                        topic=topic,
                        qos_level=Si91xMqttQos.QOS1,
                        msg_payload_len=len(message),
                        use_higher_data_len=1,
                        data_buffer=address2,
                        timeout=60,
                    )
                    publish_error = None
                    break
                except Exception as publish_ex:
                    publish_error = publish_ex
                    logger().warning(
                        f"MQTT publish attempt {publish_attempt}/{mqtt_publish_retry_count} failed: {publish_ex}"
                    )
                    time.sleep(3)
            if publish_error is not None:
                raise publish_error
            time.sleep(2)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

            assert msgs[-1].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[-1].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
            assert msgs[-1].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or message received is wrong"

            logger().info(".....Unsubscribe from the topic.....")
            mqtt_client.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
            host_topic_subscribed = False
            unsubscribe_error = None
            for unsubscribe_attempt in range(1, mqtt_unsubscribe_retry_count + 1):
                try:
                    wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic, timeout=60)
                    unsubscribe_error = None
                    break
                except Exception as unsubscribe_ex:
                    unsubscribe_error = unsubscribe_ex
                    logger().warning(
                        f"MQTT unsubscribe attempt {unsubscribe_attempt}/{mqtt_unsubscribe_retry_count} failed: {unsubscribe_ex}"
                    )
                    time.sleep(3)
            if unsubscribe_error is not None:
                raise unsubscribe_error
            dut_topic_subscribed = False
            disconnect_error = None
            for disconnect_attempt in range(1, mqtt_disconnect_retry_count + 1):
                try:
                    wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler(timeout=60)
                    disconnect_error = None
                    break
                except Exception as disconnect_ex:
                    disconnect_error = disconnect_ex
                    logger().warning(
                        f"MQTT disconnect attempt {disconnect_attempt}/{mqtt_disconnect_retry_count} failed: {disconnect_ex}"
                    )
                    time.sleep(3)
            if disconnect_error is not None:
                raise disconnect_error
            dut_mqtt_connected = False
            if getattr(mqtt_client.interfaces.mqtt, "client", None) is not None:
                mqtt_client.interfaces.mqtt.mqtt_client_close()
                host_mqtt_connected = False
            time.sleep(3)

            wifi_obj.disconnect()
            time.sleep(3)

        notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        assert len(notifications) > initial_notification_count, "received data is empty"
        logger().info(f"notifications received on remote :{notifications}")

        wifi_dut.interfaces.wifi.memory_free(address2)
        wifi_dut.interfaces.wifi.memory_free(topic_address1)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if topic is not None and host_topic_subscribed and getattr(mqtt_client.interfaces.mqtt, "client", None) is not None:
            try:
                mqtt_client.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
                host_topic_subscribed = False
            except Exception as host_unsub_ex:
                logger().warning(f"Host MQTT unsubscribe cleanup skipped due to error: {host_unsub_ex}")
        if host_mqtt_connected and getattr(mqtt_client.interfaces.mqtt, "client", None) is not None:
            try:
                mqtt_client.interfaces.mqtt.mqtt_client_close()
                host_mqtt_connected = False
            except Exception as host_disc_ex:
                logger().warning(f"Host MQTT disconnect cleanup skipped due to error: {host_disc_ex}")
        if hasattr(wifi_dut.interfaces, "mqtt"):
            if topic is not None and dut_topic_subscribed:
                try:
                    wifi_dut.interfaces.mqtt.paho_mqtt_client_unsubscribe_command_handler(topic=topic)
                    dut_topic_subscribed = False
                except Exception as dut_unsub_ex:
                    logger().warning(f"DUT MQTT unsubscribe cleanup skipped due to error: {dut_unsub_ex}")
            if dut_mqtt_connected:
                try:
                    wifi_dut.interfaces.mqtt.paho_mqtt_client_disconnect_command_handler()
                    dut_mqtt_connected = False
                except Exception as dut_disc_ex:
                    logger().warning(f"DUT MQTT disconnect cleanup skipped due to error: {dut_disc_ex}")
        if ca_cert_address is not None:
            try:
                wifi_dut.interfaces.wifi.memory_free(ca_cert_address)
                ca_cert_address = None
            except Exception as cert_free_ex:
                logger().warning(f"CA cert memory cleanup skipped due to error: {cert_free_ex}")
        if ble_obj is not None:
            try:
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            except Exception:
                pass
            try:
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
            except Exception:
                pass
            if ble_service_created:
                service_removed = False
                for cleanup_attempt in range(1, 6):
                    try:
                        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
                        ble_service_created = False
                        service_removed = True
                        break
                    except Exception as service_remove_ex:
                        logger().warning(
                            f"BLE service cleanup attempt {cleanup_attempt}/5 failed: {service_remove_ex}"
                        )
                        time.sleep(2)
                if not service_removed:
                    logger().warning("BLE service cleanup skipped after 5 attempts")
            ble_cleanup_done = False
            for cleanup_attempt in range(1, 6):
                try:
                    ble_obj.ble_cleanup()
                    ble_cleanup_done = True
                    break
                except Exception as cleanup_ex:
                    logger().warning(
                        f"BLE cleanup attempt {cleanup_attempt}/5 failed: {cleanup_ex}"
                    )
                    time.sleep(2)
            if not ble_cleanup_done:
                logger().warning("BLE cleanup skipped after 5 attempts")
        # ble_clients[0].interfaces.bluetooth.close()
