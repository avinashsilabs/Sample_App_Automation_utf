import pytest
import time
import re
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, \
    Si91xBLECustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xJoinFeatureBitMap
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf_wiseconnect_3.tests.devices.si91x import Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.stopwatch import Stopwatch
import string
import random
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs

"""
    Setup requirement:
        1. Soc board
        2. Raspberry PI4
        3. Access Point with TWT Support(Third Party AP's)
        4. Sniffer(NUC device)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Validate MQTT Functionality
        6. Validate BLE Functionality

    Author: Saurabh Sharma

"""


# Define logger
def logger():
    return get_logger(__name__)


class WifiJoinThread(ThreadBase):
    dut_addr = {}

    def __init__(
            self,
            wifi_sniffer=None,
            wifi_dut=None,
            wifi_access_point=None,
            testcase=None,
            wifi_client=None,
            net_perf_client=None,
            protocol=None,
            test_type=None,
            sl_collections=None,
            ping_count=None,
            sniffer_filter=None,
            region=None,
            switch=None,
            pmk_enable=False,
            tcp_ip_bypass=False,
            enc="ccmp",
            timeout=30,
            mqtt_server=None,
            mqtt_client=None,
            message=None,
            topic=None,
            topic1=None,
            topic2=None,
            utf_constants=None,
            qos=None,
            topic_wild=None,
            topic_wild_2=None,
            address=None,
            topic_address1=None,
            topic_address2=None

    ):
        super().__init__()
        # Define all the parameters

        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.region = region
        self.switch = switch
        self.pmk_enable = pmk_enable
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.tcp_ip_bypass = tcp_ip_bypass
        self.enc = enc
        self.timeout = timeout
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.message = message
        self.topic = topic
        self.topic1 = topic1
        self.topic2 = topic2
        self.utf_constants = utf_constants
        self.qos = qos
        self.topic_wild = topic_wild
        self.topic_wild_2 = topic_wild_2
        self.address = address
        self.topic_address1 = topic_address1
        self.topic_address2 = topic_address2

        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def run(self):
        try:
            if self.test_type == 538055:
                self.mqtt_publish_tx()

            if self.test_type == 538054:
                self.sntp_date_time()
            if self.test_type == '538053' or self.test_type == 538054:
                self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
                self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
                    client_id="Si91x_mqtt_client", server_port=8883, qos=self.qos, is_connection_encrypted=True)

                logger().info(".....DUT connects to MQTT server.....")
                self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
                time.sleep(25)
                logger().info(".....MQTT Client connects to MQTT server.....")
                self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
                    server=self.mqtt_server.interfaces.mqtt)
                time.sleep(5)

                logger().info(".... MQTT Client subscribes to the topic ....")
                self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic, qos=self.qos)

                logger().info(".... DUT subscribes to the topic 1 ....")
                self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(
                    topic=self.topic, qos=self.qos, topic_address=self.topic_address1)
                time.sleep(5)

                self.mqtt_publish_rx_single_topic()
                self.mqtt_publish_tx_single_topic()
                self.unsubscribe_single_topic()
                self.mqtt_disconnect_deinit()

        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def join_to_ap(self, skip_power_save=False):

        if not self.wifi_dut.interfaces.wifi.associated:

            if skip_power_save:
                pwr_save = False
            else:
                pwr_save = self.power_save
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            WifiJoinThread.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=pwr_save,
                associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_after_power_save=True,
                ping_count=self.ping_count, pmk_enable=self.pmk_enable, tcp_ip_bypass=self.tcp_ip_bypass,
                enc=self.enc
            )
            if not self.tcp_ip_bypass:
                self.device_ip = WifiJoinThread.dut_addr["device_ip"]
            self.dut_mac_address = WifiJoinThread.dut_addr["dut_mac_address"]
            logger().info(
                f"*****************DUT_MAC_ADDR : {self.dut_mac_address}*********************"
            )
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {self.ap_mac_address}")
            return self.dut_addr

    def set_power_save(self):

        if self.power_save:

            self.wifi_dut.interfaces.wifi.set_performance_profile(
                mode="power_save_low_latency"
            )
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
            )
        else:
            logger().info("skipping power save beacause power save flag set to be false in harness")

    def mqtt_connect_ssl(self):
        try:
            self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
            self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
                client_id="Si91x_mqtt_client", server_port=8883, qos=self.qos, is_connection_encrypted=True)

            logger().info(".....DUT connects to MQTT server.....")
            self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
            time.sleep(25)
            logger().info(".....MQTT Client connects to MQTT server.....")
            self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
            time.sleep(5)
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def mqtt_connect(self):
        try:
            self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
            self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client")

            logger().info(".....DUT connects to MQTT server.....")
            self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
            time.sleep(25)
            logger().info(".....MQTT Client connects to MQTT server.....")
            self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
            time.sleep(5)
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def mqtt_subscribe_two_topic(self):
        try:
            logger().info(".... MQTT Client subscribes to the topic 1 ....")
            self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic1, qos=self.qos)

            logger().info(".... DUT subscribes to the topic 1 ....")
            self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(
                topic=self.topic1, qos=self.qos, topic_address=self.topic_address1)
            time.sleep(5)

            logger().info(".... MQTT Client subscribes to the topic 2 ....")
            self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic2, qos=self.qos)

            logger().info(".... DUT subscribes to the topic 2 ....")
            self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(
                topic=self.topic2, qos=self.qos, topic_address=self.topic_address2)
            time.sleep(5)

        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def mqtt_wild_topic_subscribe(self):
        try:
            logger().info(".... MQTT Client subscribes to the topic wild ....")
            self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic_wild, qos=self.qos)

            logger().info(".... DUT subscribes to the topic wild ....")
            self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic_wild, qos=self.qos)
            time.sleep(3)

        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def mqtt_wild_multi_topic_subscribe(self):
        try:
            logger().info(".... MQTT Client subscribes to the topic wild ....")
            self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic_wild, qos=self.qos)

            logger().info(".... DUT subscribes to the topic wild ....")
            self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic_wild, qos=self.qos)
            time.sleep(3)

            logger().info(".... MQTT Client subscribes to the topic wild 2 ....")
            self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic_wild_2, qos=self.qos)

            logger().info(".... DUT subscribes to the topic wild 2 ....")
            self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic_wild_2, qos=self.qos)
            time.sleep(3)

        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def mqtt_publish_rx_single_topic(self):
        try:
            iter_count = self.utf_constants.get("iter_count")
            for count in range(iter_count):
                logger().info(".... MQTT Client publishes message over the topic ....")
                self.mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=self.topic, payload=self.message,
                                                                     qos=self.qos)
                time.sleep(5)

                self.wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def mqtt_publish_tx_single_topic(self):
        try:
            iter_count = self.utf_constants.get("iter_count")
            for count in range(iter_count):
                logger().info(".... DUT publishes message over the topic ....")
                self.wifi_dut.interfaces.mqtt.mqtt_client_publish(
                    topic=self.topic, message=self.message, qos=self.qos)
                time.sleep(5)

                self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def mqtt_publish_rx(self):
        try:
            iter_count = self.utf_constants.get("iter_count")
            for count in range(iter_count):
                logger().info(".... MQTT Client publishes message over the topic 1 ....")
                self.mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=self.topic1, payload=self.message,
                                                                     qos=self.qos)
                time.sleep(5)

                logger().info(".... MQTT Client publishes message over the topic 2 ....")
                self.mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=self.topic2, payload=self.message,
                                                                     qos=self.qos)
                time.sleep(5)

                self.wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def mqtt_publish_tx(self):
        try:
            iter_count = self.utf_constants.get("iter_count")
            for count in range(iter_count):
                logger().info(".... DUT publishes message over the topic 1 ....")
                self.wifi_dut.interfaces.mqtt.mqtt_client_publish(
                    topic=self.topic1, message=self.message, qos=self.qos)
                time.sleep(5)

                logger().info(".... DUT publishes message over the topic 2 ....")
                self.wifi_dut.interfaces.mqtt.mqtt_client_publish(
                    topic=self.topic2, message=self.message, qos=self.qos)
                time.sleep(5)

            self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def unsubscribe_two_topic(self):
        try:
            logger().info("....Unsubscribing from the topic1....")
            self.wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=self.topic1)
            time.sleep(5)

            logger().info("....Unsubscribing from the topic2....")
            self.wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=self.topic2)
            time.sleep(5)
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def unsubscribe_single_topic(self):
        try:
            logger().info("....Unsubscribing from the topic....")
            self.wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=self.topic)
            time.sleep(5)
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def mqtt_disconnect_deinit(self):
        try:
            logger().info("....disconnecting from MQTT broker....")
            self.wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
            time.sleep(5)

            logger().info("....calling de-init API....")
            self.wifi_dut.interfaces.mqtt.mqtt_client_deinit()
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def wlan_leave(self):
        try:
            logger().info("....Disconnection DUT from Acess Point....")
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

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

    def mqtt_rejoin(self):
        self.mqtt_publish_rx_single_topic()
        logger().info("Turning off the AP")
        self.switch.interfaces.pdu_switch.turn_off(delay=20)

        logger().info("Successfully powered off AP")
        time.sleep(60)
        self.rejoin_async_event()
        logger().info("Again turning on the AP")
        self.switch.interfaces.pdu_switch.turn_on(delay=100)

        WifiJoinThread.dut_addr = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, retry_count=3, associated=False)
        self.mqtt_connect_ssl()
        self.mqtt_wild_topic_subscribe()
        self.mqtt_publish_rx_single_topic()
        self.unsubscribe_single_topic()
        self.mqtt_disconnect_deinit()

    def sntp_date_time(self):
        try:
            sw = Stopwatch()
            while sw.elapsed_sec < 60:
                logger().info("**************** Creating SNTP Client Session in DUT ***************")
                self.wifi_dut.interfaces.wifi.sntp_client_start()
                time.sleep(10)
                logger().info("**************** Getting SNTP Time and DATE from DUT ***************")
                sntp_time, sntp_date = self.wifi_dut.interfaces.wifi.sntp_get_time_data()
                logger().info(f">>>>>>>>>>>>>>> SNTP TIME ----> '{sntp_time}'")
                logger().info(f">>>>>>>>>>>>>>> SNTP DATE ----> '{sntp_date}'\n")
                logger().info("**************** Getting SNTP Server Information from DUT ***************")
                ip_version, sntp_method, sntp_server_address = self.wifi_dut.interfaces.wifi.sntp_get_server_info()
                logger().info(f">>>>>>>>>>>>>>> SNTP SERVER {ip_version}")
                logger().info(f">>>>>>>>>>>>>>> SNTP SERVER ADDRESS: {sntp_server_address}")
                logger().info(f">>>>>>>>>>>>>>> SNTP {sntp_method}\n")
                logger().info("**************** Deleting SNTP Client Session in DUT ***************")
                self.wifi_dut.interfaces.wifi.sntp_client_stop()
                time.sleep(20)
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def iperf(self):
        try:
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f".... Remote device ip :{host_ip} ....")
            logger().info(f'**** {WifiJoinThread.dut_addr["device_ip"]} ****')
            self.sl_collections.run_traffic(
                wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
                device_ip=self.dut_addr["device_ip"], host_ip=host_ip, timeout=self.timeout)

        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)


class iperfThread(WifiJoinThread, ThreadBase):
    def __init__(
            self,
            wifi_sniffer=None,
            wifi_dut=None,
            wifi_access_point=None,
            net_perf_client=None,
            protocol=None,
            sl_collections=None,
            ping_count=None,
            sniffer_filter=None,
            wifi_client=None,
            traffic_type=None
    ):
        super().__init__()
        # Define all the parameters

        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.wifi_client = wifi_client
        self.traffic_type = traffic_type
        self.dut_mac_address = None
        self.ap_mac_address = None

    def run(self):
        try:
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f".... Remote device ip :{host_ip} ....")
            logger().info(f'**** {WifiJoinThread.dut_addr["device_ip"]} ****')
            self.sl_collections.run_traffic(
                wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
                device_ip=WifiJoinThread.dut_addr["device_ip"], host_ip=host_ip, timeout=self.timeout)

        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)


class ble_device_state:
    connected_adv = 9  # 8 for connection + 1 for advertising
    connected_scanning = 10  # 10 for connection and scanning
    connected_state = 8  # 8 for ble connection state


class BleThreadFunctionality(ThreadBase):
    ble_client_address = {}

    def __init__(self, wifi_dut=None, ble_client=None, sl_collections=None, test_case=None,
                 ble_dut=None, utf_constants=None, ble_dut_address=None, ble_client_address=None,
                 ble_clients=None, svc=None, charc=None, write_handle=None, address=None, char_uid=None, char_path=None,
                 ble_conn_interval_min=160, ble_conn_interval_max=160, set_smp=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = ble_dut_address
        self.ble_client_address = ble_client_address
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.utf_constants = utf_constants
        self.ble_clients = ble_clients
        self.ble_conn_interval_min = ble_conn_interval_min
        self.ble_conn_interval_max = ble_conn_interval_max
        self.set_smp = set_smp
        self.svc = svc
        self.charc = charc
        self.write_handle = write_handle
        self.address = address
        self.char_uid = char_uid
        self.char_path = char_path

        """ **************** Set up DUT for BLE advertising **************** """
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=self.set_smp)

        assert (self.ble_dut_address is not None), "Unable to fetch bluetooth address from DUT"
        logger().info(f" BLE DUT ADDRESS : {self.ble_dut_address}")
        time.sleep(5)

        # if self.test_case == '538053':
        #     for count in range(0, 3):
        #         logger().info(f'.... Iteration {count} ....')
        #
        #         logger().info("******************** initializing ble in remote device ********************")
        #         BleThreadFunctionality.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
        #             bt_dut_address=self.ble_dut_address)
        #         assert BleThreadFunctionality.ble_client_address, "failed to initialize ble in remote device"
        #
        #         logger().info("******************** start scanning in dut ********************")
        #         self.ble_dut.interfaces.bluetooth.ble_start_scanning(
        #             ble_client_address=BleThreadFunctionality.ble_client_address, timeout=100)
        #         self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
        #
        #         logger().info(f".... initiating ble connection ....")
        #         self.ble_dut.interfaces.bluetooth.ble_connect(
        #             ble_remote_dev_address=BleThreadFunctionality.ble_client_address)
        #
        #         logger().info(".... checking for ble connectivity stability ....")
        #         time.sleep(60)
        #
        #         logger().info("..... Checking connection status of BLE .....")
        #         state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        #         state_int = int(state) if state.isdigit() else -1
        #         assert state_int == BLEDeviceState.Connected, ".... DUT BLE device is not in connected state ...."
        #
        #         logger().info(".... disconnecting from remote device ....")
        #         self.ble_dut.interfaces.wifi.ble_disconnect(
        #             ble_remote_dev_address=BleThreadFunctionality.ble_client_address)
        #         time.sleep(3)
        #         self.ble_client.interfaces.bluetooth.close()
        #         time.sleep(20)

    def test_case_538049_538051(self):
        svc = 'HealthThermometerService'

        logger().info("******************** initializing ble in remote device ********************")
        BleThreadFunctionality.ble_client_address = self.ble_clients[0].interfaces.bluetooth.start_smp_adv(
            bt_dut_address=self.ble_dut_address, service_classes=[svc])
        assert BleThreadFunctionality.ble_client_address, "failed to initialize ble in remote device"

        logger().info("******************** start scanning in dut ********************")
        self.wifi_dut.interfaces.wifi.ble_start_scanning(
            ble_client_address=BleThreadFunctionality.ble_client_address, timeout=100)
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()

        logger().info("..... initiating connection .....")
        self.wifi_dut.interfaces.bluetooth.ble_connect(
            ble_remote_dev_address=BleThreadFunctionality.ble_client_address,
            ble_conn_interval_min=self.ble_conn_interval_min,
            ble_conn_interval_max=self.ble_conn_interval_max, ble_scan_interval=50, ble_scan_window=50)

        logger().info(".... checking for ble connectivity stability ....")
        time.sleep(60)

        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "device is in disconnection state"

        self.wifi_dut.interfaces.wifi.ble_set_smp()
        self.sl_collections.check_ble_advertise_functionality(
            wifi_dut=self.wifi_dut, ble_client=self.ble_clients[1], ble_dut_address=self.ble_dut_address,
            timeout=20)
        time.sleep(2)

    def test_case_538050_538056(self):
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1)

        BleThreadFunctionality.ble_client_address = self.sl_collections.check_ble_advertise_functionality(
            wifi_dut=self.wifi_dut, ble_client=self.ble_clients[0], ble_dut_address=self.ble_dut_address,
            timeout=20)

        logger().info(f'*** ble client address is : {BleThreadFunctionality.ble_client_address}')

        logger().info("*********************** connect to ble dut ***********************")
        self.ble_clients[0].interfaces.bluetooth.pair_and_connect(self.ble_dut_address)
        time.sleep(30)

        logger().info("******************** get connection state")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == ble_device_state.connected_state, "DUT BLE device is not in connected state"

        self.wifi_dut.interfaces.wifi.ble_set_smp(set_smp=1)
        self.sl_collections.check_ble_scan_functionality(
            wifi_dut=self.wifi_dut, ble_client=self.ble_clients[1], ble_address=self.ble_dut_address,
            timeout=20)
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()

    def test_case_538055(self):
        BleThreadFunctionality.ble_client_address = self.sl_collections.ble_connection(
            wifi_dut=self.wifi_dut, ble_client=self.ble_clients[1], ble_dut_address=self.ble_dut_address,
            timeout=20, dev_state=8, mode='master')

        logger().info("..... checking for ble connection stability ......")
        time.sleep(60)
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

        self.wifi_dut.interfaces.wifi.ble_set_smp(set_smp=0)

        BleThreadFunctionality.ble_client_address = self.sl_collections.ble_connection(
            wifi_dut=self.wifi_dut, ble_client=self.ble_clients[0], ble_dut_address=self.ble_dut_address,
            timeout=20, mode='slave')

        logger().info("..... checking for ble connection stability ......")
        time.sleep(60)
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

        status = self.ble_clients[0].interfaces.bluetooth.get_connection_status(self.ble_dut_address)
        logger().info(
            f"Connection status in remote device '{self.ble_clients[0].name}' is:{status}")

        status = self.ble_clients[1].interfaces.bluetooth.get_connection_status(self.ble_dut_address)
        logger().info(
            f"Connection status in remote device '{self.ble_clients[1].name}' is:{status}")

    def test_case_ble_scan_538052(self):
        logger().info(f'.... ble scanning started ....')
        self.sl_collections.check_ble_scan_functionality(
            wifi_dut=self.wifi_dut, ble_client=self.ble_clients[1], ble_address=self.ble_dut_address,
            timeout=20)

    def profile_fetch_module_ble_rx(self):
        self.svc = 'HealthThermometerService'
        self.charc = 'CustomNotifyCharacteristic'

        logger().info(f"******************** get all profiles ********************")
        uuids = self.wifi_dut.interfaces.wifi.ble_get_profiles_async(
            ble_remote_dev_address=BleThreadFunctionality.ble_client_address)
        assert HealthThermometerService.UUID.lower() in uuids is not None, "Could not fetch health " \
                                                                           "thermometer profile "

        logger().info(" ******************** Resolving Profile ********************")
        start_handle, end_handle, data = self.wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=BleThreadFunctionality.ble_client_address,
            uuid=int(HealthThermometerService.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."

        char_uuids, write_handles, char_properties = self.wifi_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=BleThreadFunctionality.ble_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60)
        logger().info(
            f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
            f"{char_properties}")

        assert CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID in char_uuids, "Unable to find {} uuid".format(
            CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID)
        index = char_uuids.index(CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID)
        logger().info(f"UUID's are:{char_uuids}")
        logger().info(f"write_handles:{write_handles}")
        logger().info(f"index:{index}")
        assert char_properties[index].isdigit(), "Character property found is not an integer"
        assert CustomNotifyCharacteristic.prop_int == int(
            char_properties[index]), "Invalid character property found"

        self.write_handle = int(write_handles[index], 16)
        logger().info(f"write_handle:{self.write_handle}")
        assert self.write_handle > 0, "Unable to get write handle for configured service"

    def profile_fetch_module_ble_tx(self):
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        self.char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        servs, chars = self.ble_clients[0].interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        self.char_path, char_props = self.ble_clients[0].interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs, service_uid=service_uid, char_uid=self.char_uid)
        assert self.char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"

        # self.ble_clients[0].interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=self.char_path)

        logger().info(f' *********************** subscribe to notifications ***********************')
        self.ble_clients[0].interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_clients[0].interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path, char_uid=self.char_uid)
        time.sleep(3)

    def run(self):
        if self.test_case in [538054]:
            connection_interval = [45, 125, 250, 500]

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

                logger().info("..... checking for ble connection stability ......")
                time.sleep(30)

            logger().info("..... Checking connection status of BLE .....")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, ".... DUT BLE device is not in connected state ...."

        if self.test_case in [538049, 538051]:
            self.wifi_dut.interfaces.wifi.ble_set_att_value(
                ble_remote_dev_address=BleThreadFunctionality.ble_client_address,
                handle=(self.write_handle + 1), enable_notify=1)
            time.sleep(1)

            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
            sw = Stopwatch()
            while sw.elapsed_sec < 60:
                since_time = time.perf_counter_ns()
                self.ble_clients[0].interfaces.bluetooth.send_gatt_charc_notification(self.svc, self.charc, data)
                time.sleep(3)
                tw = Stopwatch()
                while tw.elapsed_sec < 10:
                    events = self.wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                    for event in events:
                        if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                            logger().info(
                                f"************** BLE EVENT DATA IS : {event.event_data} **************")
                            received_data = re.findall(r"(\b[A-Z0-9]{20}\b)", event.event_data)
                            logger().info(f"******* Received Data on DUT : {received_data} ********")
                            assert received_data == [data], "data mismatched"

            self.wifi_dut.interfaces.bluetooth.ble_set_att_value(
                ble_remote_dev_address=BleThreadFunctionality.ble_client_address, handle=(self.write_handle + 1),
                enable_notify=0)

        if self.test_case == 538050:
            self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                ble_remote_dev_address=BleThreadFunctionality.ble_client_address, buffer_mode=1, buffer_count=2)

            sw = Stopwatch()
            count = 0
            while sw.elapsed_sec < 60:
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
                self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                    ble_remote_dev_address=BleThreadFunctionality.ble_client_address, data=data,
                    data_address=self.address)
                time.sleep(10)
                logger().info("******************** Validate Data ********************")
                notifications = self.ble_clients[0].interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
                logger().info(
                    f' *********************** Notification is {notifications} ***********************')
                assert len(notifications) > 0, "received data is empty"
                assert notifications[count] == data, "Data Mismatched"
                count += 1

            logger().info(f' *********************** unsubscribe to notifications ***********************')
            self.ble_clients[0].interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
            self.ble_client[0].interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
            time.sleep(1)

        if self.test_case == 538052:
            for count in range(0, 2):
                if count == 1:
                    logger().info("..... initializing ble ......")
                    self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=self.set_smp)
                    assert (self.ble_dut_address is not None), "Unable to fetch bluetooth address from DUT"
                    logger().info(f" BLE DUT ADDRESS : {self.ble_dut_address}")
                    time.sleep(5)

                connection_interval = [45]
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

                    logger().info("..... checking for ble connection stability ......")
                    time.sleep(30)

                logger().info("..... Checking connection status of BLE .....")
                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, ".... DUT BLE device is not in connected state ...."

                self.ble_cleanup()
                self.ble_clients[0].interfaces.bluetooth.close()
                self.ble_clients[1].interfaces.bluetooth.close()

    def update_conn_param(self):
        self.wifi_dut.interfaces.wifi.ble_update_conn_param(
            ble_remote_dev_address=BleThreadFunctionality.ble_client_address, ble_conn_interval_min=45,
            ble_conn_interval_max=45, ble_conn_latency=0, ble_supervision_timeout=2000)

    def ble_remove_services(self):
        logger().info("***** ble_remove_service *****")
        self.wifi_dut.interfaces.wifi.ble_remove_service()

    def ble_cleanup(self):
        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            logger().info("Device is in connected status try to disconnect")
            self.wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=BleThreadFunctionality.ble_client_address)
            time.sleep(5)
        elif state_int == 2:
            logger().info("Device is in scanning status try to stop scanning")
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        elif state_int == 1:
            logger().info("Device is in advertising status try to stop advertising")
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        elif state_int == 3:
            logger().info("Device is in scanning status try to stop scanning")
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            logger().info("Device is advertising status try to stop advertising")
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        elif state_int == 9:
            logger().info("Device is in connected status try to disconnect")
            self.wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=BleThreadFunctionality.ble_client_address)
            logger().info("Device is in advertising status try to stop advertising")
            time.sleep(5)
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        elif state_int == 10:
            logger().info("Device is in connected status try to disconnect")
            self.wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=BleThreadFunctionality.ble_client_address)
            logger().info("Device is advertising status try to stop advertising")
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        elif state_int == 0:
            logger().info("Device is in idle status")
        else:
            logger().info("Device is in unknown state")
            self.wifi_dut.interfaces.wifi.is_dut_bad_state = True
        logger().info(" *************DUT Cleanup Success *******************")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_mqtt_conn_subs_disconn_loop_when_ble_rx_smp_c538049(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_clients, mqtt_client, mqtt_server):
    """QOS1:Verify whether DUT is able to do simultaneous publish and subscribe from 2 different topics with MQTT over
    SSL(with different topic lengths) MQTT init-MQTT connect-subscribe-publish-disconnect-MQTT deinit while BLE Rx in SMP"""

    ble_obj = None
    try:
        test_name = request.node.name
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic1 = 'weather'
        topic2 = 'precipitation'
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))

        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                                  sniffer_filter=sniffer_filter, topic1=topic1, topic2=topic2, message=message,
                                  mqtt_client=mqtt_client, mqtt_server=mqtt_server, utf_constants=utf_constants,
                                  ping_count=ping_count, qos=1)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_clients=ble_clients, utf_constants=utf_constants,
                                         ble_conn_interval_min=250, ble_conn_interval_max=250, set_smp=1,
                                         test_case=538049)

        ble_obj.test_case_538049_538051()

        for count in range(0, 2):
            logger().info(f'.... MQTT functionality running in a loop of iteration count {count} ....')
            wifi_obj.join_to_ap(skip_power_save=True)
            if count != 1:
                ble_obj.profile_fetch_module_ble_rx()
            wifi_obj.mqtt_connect_ssl()
            wifi_obj.set_power_save()
            wifi_obj.mqtt_subscribe_two_topic()
            wifi_obj.mqtt_publish_tx()
            if count != 1:
                ble_obj.start()
                time.sleep(35)
            wifi_obj.mqtt_publish_rx()
            ble_obj.wait_for_exit()
            wifi_obj.unsubscribe_two_topic()
            wifi_obj.mqtt_disconnect_deinit()
            wifi_obj.wlan_leave()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()
        ble_clients[0].interfaces.bluetooth.close()
        ble_clients[1].interfaces.bluetooth.close()


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_single_multi_wildcard_when_ble_tx_smp_c538050(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_clients, mqtt_client, mqtt_server):
    """Test DUT functionality by subscribing to an MQTT topic using both single-level (+) and multi-level (#) wildcards,
     and simultaneously receive data while transmitting 240 bytes over BLE with DLE enabled"""

    ble_obj = None
    try:
        test_name = request.node.name
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic_wild = "patch/+/properties/desired/#"
        topic = "patch/iothub/properties/desired/sensor"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))

        ping_count = utf_constants.get("ping_count")

        logger().info("***** configure and start the Sniffer *****")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                                  sniffer_filter=sniffer_filter, topic=topic, topic_wild=topic_wild, message=message,
                                  mqtt_client=mqtt_client, mqtt_server=mqtt_server, utf_constants=utf_constants,
                                  ping_count=ping_count, qos=1, address=address2)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_clients=ble_clients, utf_constants=utf_constants,
                                         address=address2, test_case=538050)

        # ble_obj_tx = Ble_Data_Transfer_Tx(wifi_dut=wifi_dut, ble_clients=ble_clients, address=address2,
        #                                   sl_collections=sl_collections, ble_dut=ble_dut)

        ble_obj.test_case_538050_538056()
        ble_obj.update_conn_param()
        wifi_obj.join_to_ap(skip_power_save=True)
        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_wild_topic_subscribe()
        ble_obj.profile_fetch_module_ble_tx()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.mqtt_publish_rx_single_topic()
        wifi_obj.mqtt_publish_tx_single_topic()
        ble_obj.ble_remove_services()
        wifi_obj.unsubscribe_single_topic()
        wifi_obj.mqtt_disconnect_deinit()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.memory_free(address2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup()
        ble_clients[0].interfaces.bluetooth.close()
        ble_clients[1].interfaces.bluetooth.close()


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_check_rejoin_hit_with_wildcard_and_ble_rx_smp_c538051(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_clients, mqtt_client, mqtt_server, switch):
    """Verify DUT functionality  with MQTT subscription topic used combination of single level(+) and multilevel
    wild card(#) characters after rejoin failure indication using emb_mqtt while BLE Rx 20 bytes of data"""

    ble_obj=None
    try:
        test_name = request.node.name
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic_wild = "patch/+/properties/desired/#"
        topic = "patch/iothub/properties/desired/sensor"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))

        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=3, scan_interval=4, beacon_missed_count=40, first_time_retry_enable=0)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                                  sniffer_filter=sniffer_filter, topic=topic, topic_wild=topic_wild, message=message,
                                  mqtt_client=mqtt_client, mqtt_server=mqtt_server, utf_constants=utf_constants,
                                  ping_count=ping_count, switch=switch, qos=1)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_clients=ble_clients, utf_constants=utf_constants,
                                         ble_conn_interval_min=250, ble_conn_interval_max=250, set_smp=1,
                                         address=address2, test_case=538051)

        wifi_obj.join_to_ap(skip_power_save=True)
        wifi_obj.set_power_save()
        ble_obj.test_case_538049_538051()
        ble_obj.profile_fetch_module_ble_rx()
        wifi_obj.mqtt_connect_ssl()
        wifi_obj.mqtt_wild_topic_subscribe()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.mqtt_rejoin()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.memory_free(address2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()
        ble_clients[0].interfaces.bluetooth.close()
        ble_clients[1].interfaces.bluetooth.close()


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
def test_wifi_sdk_mqtt_subs_two_topic_ble_conn_disconn_loop_c538052(
        wifi_access_point, wifi_dut, request, sl_collections, wifi_client, wifi_sniffer,
        ble_dut, utf_constants, ble_clients, mqtt_client, mqtt_server):
    """QOS0:Verify whether DUT is able to subscribe to 2 topics with 2 different lengths and able to receive data on
    both subscribed topics(with different lengths) over MQTT SSL while BLE advertise, connect, disconnect in a loop"""

    ble_obj = None
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_data_length_20_bytes_C19920.log"):
            test_name = request.node.name
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

            topic1 = 'weather'
            topic2 = 'precipitation'
            message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))

            ping_count = utf_constants.get("ping_count")

            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            logger().info("start capturing with Sniffer by giving the test case name as filename")

            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

            topic_address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic1) + 1)
            wifi_dut.interfaces.wifi.load_memory(address=topic_address1, size=len(topic1), write_content=topic1)

            topic_address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic2) + 1)
            wifi_dut.interfaces.wifi.load_memory(address=topic_address2, size=len(topic2), write_content=topic2)

            wifi_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                      testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                                      topic1=topic1, topic2=topic2, message=message, wifi_sniffer=wifi_sniffer,
                                      mqtt_client=mqtt_client, mqtt_server=mqtt_server, utf_constants=utf_constants,
                                      ping_count=ping_count, topic_address1=topic_address1, topic_address2=topic_address2,
                                      qos=0)

            ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                             ble_dut=ble_dut, ble_clients=ble_clients, utf_constants=utf_constants,
                                             set_smp=0, test_case=538052)

            ble_obj.test_case_ble_scan_538052()
            wifi_obj.join_to_ap(skip_power_save=True)
            wifi_obj.mqtt_connect_ssl()
            wifi_obj.set_power_save()
            ble_obj.start()
            wifi_obj.mqtt_subscribe_two_topic()
            wifi_obj.mqtt_publish_rx()
            ble_obj.wait_for_exit()
            wifi_obj.unsubscribe_two_topic()
            wifi_obj.mqtt_disconnect_deinit()
            logger().info(".... stop the sniffer ....")
            wifi_sniffer.interfaces.capture.stop_capture()

            wifi_dut.interfaces.wifi.memory_free(topic_address1)
            wifi_dut.interfaces.wifi.memory_free(topic_address2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.skip("observing BLE disconnection issue in dual role scenario")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 4})
def test_wifi_sdk_mqtt_subs_ble_dual_conn_c538055(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_clients, mqtt_client, mqtt_server):
    """Verify whether DUT is able to connect to EMB MQTT server over SSL, do subscribe and publish after one central
    and one peripheral BLE connection."""

    ble_obj=None
    try:
        test_name = request.node.name
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic1 = 'weather'
        topic2 = 'precipitation'
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))

        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(message) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(message), write_content=message)

        topic_address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic1) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=topic_address1, size=len(topic1), write_content=topic1)

        topic_address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(topic2) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=topic_address2, size=len(topic2), write_content=topic2)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                                  sniffer_filter=sniffer_filter, topic1=topic1, topic2=topic2, message=message,
                                  mqtt_client=mqtt_client, mqtt_server=mqtt_server, utf_constants=utf_constants,
                                  ping_count=ping_count, address=address2, qos=1, topic_address1=topic_address1,
                                  topic_address2=topic_address2, test_type=538055)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_clients=ble_clients, utf_constants=utf_constants,
                                         set_smp=1, test_case='538055')

        ble_obj.test_case_538055()
        wifi_obj.join_to_ap(skip_power_save=True)
        wifi_obj.mqtt_connect_ssl()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_two_topic()
        wifi_obj.start()
        time.sleep(3)
        wifi_obj.mqtt_publish_rx()
        wifi_obj.wait_for_exit()
        wifi_obj.unsubscribe_two_topic()
        wifi_obj.mqtt_disconnect_deinit()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.memory_free(address2)
        wifi_dut.interfaces.wifi.memory_free(topic_address1)
        wifi_dut.interfaces.wifi.memory_free(topic_address2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()
        ble_clients[0].interfaces.bluetooth.close()
        ble_clients[1].interfaces.bluetooth.close()


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_multi_wildcard_when_ble_tx_smp_c538056(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_clients, mqtt_client, mqtt_server):
    """Verify whether DUT is able to subscribe to 2 topics with single and multi level wild card  and receive the
    data on subscribed topic using emb mqtt while BLE Tx indications of data 240 bytes(DLE ON)"""

    try:
        test_name = request.node.name
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        topic_wild = "patch/+/properties/desired/#"
        topic_wild_2 = "automation/+/properties/coex/#"
        topic1 = "patch/iothub/properties/desired/sensor"
        topic2 = "automation/product/properties/coex/testplan"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))

        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                                  sniffer_filter=sniffer_filter, topic1=topic1, topic_wild=topic_wild, message=message,
                                  mqtt_client=mqtt_client, mqtt_server=mqtt_server, utf_constants=utf_constants,
                                  ping_count=ping_count, topic2=topic2, topic_wild_2=topic_wild_2, qos=1)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_clients=ble_clients, utf_constants=utf_constants,
                                         test_case='538050')

        wifi_obj.join_to_ap(skip_power_save=True)
        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_wild_multi_topic_subscribe()
        ble_obj.start()
        wifi_obj.mqtt_publish_rx()
        wifi_obj.mqtt_publish_tx()
        ble_obj.wait_for_exit()
        wifi_obj.unsubscribe_two_topic()
        wifi_obj.mqtt_disconnect_deinit()
        wifi_obj.wlan_leave()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_mqtt_iperf_ble_multi_thread_c538053(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_client, mqtt_client, mqtt_server, protocol, net_perf_client):
    """Verify whether DUT is able to connect to TCP and MQTT over SSL connection and run traffic simultaneously
    while BLE scan, connect, disconnect in a loop."""

    try:
        test_name = request.node.name

        topic = "humidity/sensor"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))

        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                                  sniffer_filter=sniffer_filter, topic=topic, message=message, qos=1,
                                  mqtt_client=mqtt_client, mqtt_server=mqtt_server, utf_constants=utf_constants,
                                  ping_count=ping_count, test_type='538053')

        iperf_obj = iperfThread(wifi_dut=wifi_dut, sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                protocol=protocol, net_perf_client=net_perf_client, wifi_client=wifi_client)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='538053', set_smp=1)

        wifi_obj.join_to_ap(skip_power_save=True)
        wifi_obj.set_power_save()
        ble_obj.start()
        time.sleep(60)
        iperf_obj.start()
        time.sleep(10)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        iperf_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        wifi_obj.wlan_leave()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.SNTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mqtt_sntp_ble_multi_thread_c538054(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_client, mqtt_client, mqtt_server):
    """Verify whether DUT is able to connect to SNTP and MQTT over SSL connection simultaneously when BLE is in idle
    SMP connection with different connection intervals(45ms, 125ms, 250ms, 500ms)"""

    ble_obj = None
    try:
        test_name = request.node.name

        topic = "weather_humidity"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))

        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                                  sniffer_filter=sniffer_filter, topic=topic, message=message, qos=1,
                                  mqtt_client=mqtt_client, mqtt_server=mqtt_server, utf_constants=utf_constants,
                                  ping_count=ping_count, test_type=538054)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case=538054)

        wifi_obj.join_to_ap(skip_power_save=True)
        wifi_obj.set_power_save()
        ble_obj.start()
        time.sleep(60)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()
        ble_client.interfaces.bluetooth.close()
