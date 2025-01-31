import string
import time
import pytest
import ipaddress
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
    Si91xMqttQos
)
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService, \
    BodySensorLocationCharacteristic, HeartRateMeasurementCharacterstic
from utf.utils.stopwatch import Stopwatch
import re
def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcpv6 and get IPV6 address
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from/to the dut to IPV6 address
        5. scan ,connect, data transfer
        6. ble connection slave/master
    Author: Swathi.Chinthala

"""
import ipaddress
import random


def random_ipv6_addr(network):
    """
    Generate a random IPv6 address in the given network
    Example: random_ipv6_addr("fd66:6cbb:8c10::/48")
    Returns an IPv6Address object.
    """
    net = ipaddress.IPv6Network(network)
    # Which of the network.num_addresses we want to select?
    addr_no = random.randint(0, net.num_addresses)
    # Create the random address by converting to a 128-bit integer, adding addr_no and converting back
    network_int = int.from_bytes(net.network_address.packed, byteorder="big")
    addr_int = network_int + addr_no
    addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
    return addr

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
            gatt=False,
            service_class=None,
            conn_interval=200,
            char_path=None, char_uid=None, data=None,
            data_length=20, data_duration=60, periodic_delay=1, service_uid=None,
            address=None,
            service_uuid=None,
            char_uuid=None,
            characteristic=None
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
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

        if self.gatt:
            # Set up DUT for BLE advertising
            logger().info("start ble GATT service in DUT")
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
                set_smp=self.ble_pairing)
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
                                        timeout=10)

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
                timeout=20
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
            min_conn_interval=self.conn_interval
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


    def gatt_write_without_resp(self, write_handle, data_length=None, data=None):
        self.wifi_dut.interfaces.wifi.ble_set_att_cmd(ble_remote_dev_address=self.ble_client_address,
                                                     handle=write_handle, data_length=data_length, data=data)


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

        if self.ble_test_type == "connect_as_master_notify_rx":
            self.ble_connect(role="master")
            self.service_discovery_on_dut()
            self.enable_notifications_remote()

        if self.ble_test_type == "gatt_write_without_resp":
            self.gatt_write_without_resp(write_handle=self.write_handle, data_length=self.data_length, data=self.data)


class WLanThread(ThreadBase):
    client_info = {"mac_address": None, "ip_address": None}
    dut_info = {"mac_address": None, "ip_address": None}

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None,
                 wifi_client=None, test_id=None, test_type=None, ping_from="remote", ping_count=10, addr_type="global",
                 traffic_type=None, protocol=None, net_perf_client=None, timeout=60, http_server=None, index_path=None,
                 http_client=None, https=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.ping_from = ping_from
        self.ping_count = ping_count
        self.test_type = test_type
        self.dut_add_dict = None
        self.addr_type = addr_type
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.http_client = http_client
        self.http_server = http_server
        self.https = https
        self.index_path = index_path
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")
        self.remote_ip = None

    def ping_async(self):
        time.sleep(10)
        logger().info(f"Ping from DUT to remote")
        self.wifi_dut.interfaces.wifi.ping(server_ip=self.remote_ip, num_ping_attempts=self.ping_count,
                                           ping_timeout=10, ip_version='ipv6', ping_size=64)

        logger().info(f"Ping successful")

    def run_http_download(self):
        logger().info("in http download method")
        self.sl_collections.http_file_download(
            wifi_dut=self.wifi_dut,
            http_server=self.http_server,
            index_path=self.index_path,
            device_ip=self.dut_add_dict['device_ip'],
            https=self.https,
        )

    def http_get(self):
        mode = True if self.https else False
        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=mode)

        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
            self.http_server.interfaces.http,
            self.index_path,
            server_port=self.http_server.interfaces.http.port,
            timeout=100)
        status_client, content_client = self.http_client.interfaces.http.http_get(
            self.http_server.interfaces.http, self.index_path)

        assert not status_dut, "failed to fetch the https data"
        assert status_client, "failed to load the https data"

        logger().info(status_dut)
        logger().info(content_dut)
        assert content_dut == content_client, "fetched data is not same as expected data"
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.http_client_deinit()


    def join_to_ap(self):

        if not self.wifi_dut.interfaces.wifi.associated:
            self.dut_add_dict = self.sl_collections. \
                join_to_wifi_network(wifi_dut=self.wifi_dut,
                                     wifi_access_point=self.wifi_access_point,
                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                     ip_version='ipv6',
                                     ping_after_power_save=False,
                                     ping_before_power_save=True,
                                     power_save=self.power_save,
                                     ipv6_type=self.addr_type,
                                     retry_count=3
                                     )
            logger().info(
                f"DUT MAC ADDRESS :  {self.dut_add_dict['dut_mac_address']} "
                f"DUT IPV6 ADDRESS : {self.dut_add_dict['device_ip']}")

        self.remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.addr_type)
        self.remote_ip = ipaddress.ip_address(self.remote_ip)
        logger().info(f"Remote device ip:{self.remote_ip}")

    def run_traffic(self, protocol="TCP", traffic_type="TX", ip_version=6):

        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=protocol,
            device_ip=self.dut_add_dict['device_ip'],
            host_ip=self.remote_ip,
            timeout=self.timeout,
            traffic_type=traffic_type,
            ip_version=ip_version,
            buffer_size_tcp=1380,
            buffer_size_udp=1390,
            async_socket=1
        )

    def run(self):

        if not self.wifi_dut.interfaces.wifi.associated:
            self.join_to_ap()

        if self.test_type == "ping":

            if self.ping_from == "remote":

                device_ip = self.dut_add_dict['device_ip']

                if self.addr_type == "link":
                    interface = self.wifi_client.interfaces.wifi.config["interface"]
                    device_ip = f"{self.dut_add_dict['device_ip']}%{interface}"

                logger().info("ping from remote to DUT")
                status = self.sl_collections.ping(device_ip=device_ip,
                                                  ping_count=self.ping_count,
                                                  retry_count=3)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
                logger().info("ping successful")

            if self.ping_from == "dut":
                self.ping_async()

            if self.ping_from == "both":
                self.ping_async()
                logger().info("ping from remote to DUT")
                status = self.sl_collections.ping(device_ip=self.dut_add_dict['device_ip'],
                                                  ping_count=self.ping_count)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
                logger().info("ping successful")

        if self.test_type == "iperf":
            self.join_to_ap()
            logger().info("Running data transfer")
            self.run_traffic(protocol=self.protocol, traffic_type=self.traffic_type)

        if self.test_type == "http_get":
            self.join_to_ap()
            self.http_get()


        if self.test_type == "http":
            self.join_to_ap()
            logger().info("Running http download")
            self.run_http_download()

# this thread used for sta+ble as a slave
class BleThreadFunctionality(ThreadBase):
    def __init__(
            self,
            wifi_dut=None,
            ble_client=None,
            ble_test_type=None,
            sl_collections=None,
            ble_scan_type=1,
            ble_pairing=0,
            dev_state=8,
            gatt=False,
            service_class=None,
            conn_interval=160,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.ble_scan_type = ble_scan_type
        self.ble_pairing = ble_pairing
        self.dev_state = dev_state
        self.gatt = gatt
        self.conn_interval = conn_interval
        self.service_class = service_class
        self.ble_client_address = None
        self.write_handle = None

        if self.gatt:
            # Set up DUT for BLE advertising
            logger().info("start ble GATT service in DUT")
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
                set_smp=self.ble_pairing)
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

    def stop_adv_scan(self):
        logger().info("Initiating stop advertise from DUT")
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info("Initiating stop scan from Remote device")
        self.ble_client.interfaces.bluetooth.stop_scanning()
        self.ble_client.interfaces.bluetooth.close()

    def stop_scan_adv(self):
        logger().info("Initiating stop scan from dut")
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("Initiating stop advertise from Remote device")
        self.ble_client.interfaces.bluetooth.stop_advertising()
        self.ble_client.interfaces.bluetooth.close()

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

    def connect_from_dut(self):

        self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                        ble_client_address=self.ble_client_address, mode="master", retries=3,
                                        ble_pairing=self.ble_pairing,
                                        dev_state=self.dev_state,
                                        max_conn_interval=self.conn_interval,
                                        min_conn_interval=self.conn_interval)
    def ble_connect(self, role="master"):

        if role == "master":
            self.check_scan_functionality()
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            self.wifi_dut.interfaces.wifi.ble_advertising = False
            self.connect_from_dut()

        else:
            logger().info("Starting DUT BLE advertising")
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            time.sleep(5)
            self.scan_and_connect_from_remote()

    def fetch_profiles(self):

        uuids = self.wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=self.ble_client_address)
        assert HeartRateService.UUID.lower() in uuids, "Unable to get HeartRateService profile of RD from DUT"

        logger().info(" ******************** Resolving Profile ********************")
        start_handle, end_handle, data = self.wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=self.ble_client_address, uuid=int(HeartRateService.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."

        char_uuids, write_handles, char_properties = self.wifi_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=self.ble_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60)
        logger().info(
            f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
            f"{char_properties}")

        assert HeartRateMeasurementCharacterstic.HR_Measure_UUID in char_uuids, "Unable to find {} uuid"
        index = char_uuids.index(HeartRateMeasurementCharacterstic.HR_Measure_UUID)
        logger().info(f"UUID's are:{char_uuids}")
        logger().info(f"write_handles:{write_handles}")
        logger().info(f"index:{index}")
        assert char_properties[index].isdigit(), "Character property found is not an integer"
        self.write_handle = int(write_handles[index], 16)
        logger().info(f"write_handle:{self.write_handle}")
        assert self.write_handle > 0, "Unable to get write handle for configured service"

    def enable_notifications(self):

        if self.write_handle:

            logger().info(f"Enabling notification on dut")
            self.wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                            handle=(self.write_handle + 1), enable_notify=1)
            time.sleep(10)

            tw = Stopwatch()
            Data_received_on_dut = []
            while tw.elapsed_sec < 60:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        if "rsi_ble_on_gatt_write_event_gatt" in event.event_data:
                            received_data = re.findall(r"att_length: 1, att_value: (.*)", event.event_data)
                            Data_received_on_dut = received_data + Data_received_on_dut
                            received_data = ord(received_data[0])
                            logger().info(f"received_data:{received_data}")
            assert len(Data_received_on_dut) > 0, "Notifications not received on DUT"
            self.wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                            handle=(self.write_handle + 1), enable_notify=0)

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
            min_conn_interval=self.conn_interval
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
    def check_scan_functionality(self):
        self.ble_client_address = self.sl_collections.check_ble_scan_functionality(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_address=self.ble_dut_address,
            ble_scan_type=1,
            timeout=60,
            services=self.service_class
        )

    def run(self):
        if self.ble_test_type == "advertise":
            self.ble_client_address = self.sl_collections.check_ble_advertise_functionality(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                timeout=20,
            )

        if self.ble_test_type == "scan":
            self.check_scan_functionality()

        if self.ble_test_type == "start_scan_stop_scan":
            # Start scanning
            self.wifi_dut.interfaces.wifi.ble_start_scanning(
                ble_client_address=self.ble_client_address, timeout=60
            )
            logger().info(
                f"Remote device found in scan results ,BLE scanning is successful"
            )
            # Stop scanning
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()

        if self.ble_test_type == "slave":
            self.ble_connect(role="slave")

        if self.ble_test_type == "master":
            self.ble_connect(role="master")

        if self.ble_test_type == "notifications":
            self.enable_notifications()

        if self.ble_test_type == "scan_from_remote_device":
            self.ble_client_address = self.sl_collections.scan_from_remote_device(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
            )

        if self.ble_test_type == "scan_and_connect_from_dut":
            self.scan_and_connect_from_dut()

        if self.ble_test_type == "scan_and_connect_from_remote":
            self.scan_and_connect_from_remote()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA3", "passphrase": "231469460",
                               "protected_management_frame": "Capable", "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
def test_Coex_sdk_WLAN_ipv6_BLE_master_C156991(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. advertise remote device
        4. Scan & connect from DUT to remote
        5. Join the access point and get ipv6 address
        6. Enable wlan and bt power save mode in dut after the connection
        7. Ping from AP backend machine to DUT's IPV6 Address.


    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_count=ping_count, wifi_client=wifi_client,
                              addr_type="link")
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notifications",
            dev_state=9,
            gatt=True,
            service_class=["HeartRateService"],
        )
        ble_obj.advertise_dut()
        ble_obj.ble_connect(role="master")
        ble_obj.fetch_profiles()
        ble_obj.start()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
def test_Coex_sdk_WLAN_ipv6_BLE_slave_C156992(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Advertise DUT
        4. Join the access point and get ipv6 address
        5. Enable wlan and bt power save mode in dut after the connection
        6. Scan from remote BLE device and connect to remote

    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_count=ping_count, wifi_client=wifi_client)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notifications",
            dev_state=10,
            gatt=True,
            service_class=["HeartRateService"]
        )

        ble_obj.advertise_dut()
        ble_client_address = sl_collections.check_ble_scan_functionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_address=ble_obj.ble_dut_address,
            timeout=60,
        )
        ble_client.interfaces.bluetooth.close()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.scan_and_connect_from_remote()
        ble_obj.fetch_profiles()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.ble_scanning = True

        wifi_sniffer.interfaces.capture.stop_capture()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_Coex_sdk_WLAN_ipv6_BLE_adv_scan_C156989(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. scan& Join to the access point and enable the dhcp
        2. Advertise DUT ,Scan from remote device
        3. Advertise remote device & Scan from DUT
        4. Enable the wlan and bt power save mode
        5. Initiate ping from the dut

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_count=ping_count, wifi_client=wifi_client, addr_type="link")
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="advertise",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        sl_collections.check_ble_scan_functionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_address=ble_obj.ble_dut_address,
            timeout=60,
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_client.interfaces.bluetooth.close()
        sl_collections.scan_from_remote_device(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_dut_address=ble_obj.ble_dut_address,
        )
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        ble_client.interfaces.bluetooth.stop_advertising()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_dut.interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA3", "passphrase": "1234567890",
                               "protected_management_frame": "Capable",
                               "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"),
                               }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_Coex_sdk_WLAN_ipv6_BLE_adv_scan_C156990(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. scan& Join to the access point and enable the dhcp
        2. Advertise DUT ,Scan from remote device
        3. Advertise remote device & Scan from DUT
        4. Enable the wlan and bt power save mode
        5. Initiate ping from the dut

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_count=ping_count, wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="advertise",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        sl_collections.check_ble_scan_functionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_address=ble_obj.ble_dut_address,
            timeout=60,
        )
        logger().info("ping from remote to DUT")
        status = sl_collections.ping(device_ip=wlan_obj.dut_add_dict['device_ip'],
                                     ping_count=ping_count,
                                     retry_count=3)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        logger().info("ping successful")
        ble_client.interfaces.bluetooth.close()
        sl_collections.scan_from_remote_device(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_dut_address=ble_obj.ble_dut_address,
        )
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        ble_client.interfaces.bluetooth.stop_advertising()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_dut.interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_Coex_sdk_WLAN_IPV6_TCP_TX_BLE_adv_scan_C538007(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        net_perf_client,
        protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Advertise DUT
        4. Join the access point and get ipv6 address
        5. Enable wlan and bt power save mode in dut after the connection
        6. Advertise remote device & Scan from DUT
        7. Start the iperf TCP server on the Remote device
        8. Start the iperf TCP client on the DUT
        9. Validate the throughput
        10.Scan from remote device , check whether the Remote is able to scan DUT

    """

    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="iperf",
                              ping_count=ping_count, wifi_client=wifi_client,
                              protocol=protocol,
                              net_perf_client=net_perf_client,
                              traffic_type="TX")

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            conn_interval=20,
        )
        ble_obj.advertise_dut()
        wlan_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_client.interfaces.bluetooth.close()
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        ble_client_address = sl_collections.scan_from_remote_device(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_dut_address=ble_obj.ble_dut_address,
        )
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                                | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_Coex_sdk_WLAN_IPV6_TCP_RX_BLE_20ms_C538020(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        net_perf_client,
        protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Advertise DUT
        4. Join the access point and get ipv6 address
        5. Enable wlan and bt power save mode in dut after the connection
        6. Scan from remote BLE device and connect to DUT
        7. Start the iperf TCP server on the DUT
        8. Start the iperf TCP client on the remote device
        9. Validate the throughput
        10.check BLE connection stability

    """

    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="iperf",
                              ping_count=ping_count, wifi_client=wifi_client,
                              protocol=protocol,
                              net_perf_client=net_perf_client,
                              traffic_type="RX")

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan_and_connect_from_remote",
            ble_pairing=1,
            conn_interval=20,
        )
        ble_obj.advertise_dut()
        wlan_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_Coex_sdk_WLAN_IPV6_TCP_RX_BLE_112ms_C538021(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        net_perf_client,
        protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Advertise DUT
        4. Join the access point and get ipv6 address
        5. Enable wlan and bt power save mode in dut after the connection
        6. Scan from remote BLE device and connect to DUT
        7. Start the iperf TCP server on the DUT
        8. Start the iperf TCP client on the remote device
        9. Validate the throughput
        10.check BLE connection stability

    """

    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="iperf",
                              ping_count=ping_count, wifi_client=wifi_client,
                              protocol=protocol,
                              net_perf_client=net_perf_client,
                              traffic_type="RX")

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan_and_connect_from_remote",
            ble_pairing=1,
            conn_interval=112,
        )
        ble_obj.advertise_dut()
        wlan_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_Coex_sdk_WLAN_IPV6_TCP_RX_BLE_4000ms_C538022(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        net_perf_client,
        protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Advertise DUT
        4. Join the access point and get ipv6 address
        5. Enable wlan and bt power save mode in dut after the connection
        6. Scan from remote BLE device and connect to DUT
        7. Start the iperf TCP server on the DUT
        8. Start the iperf TCP client on the remote device
        9. Validate the throughput
        10.check BLE connection stability

    """

    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="iperf",
                              ping_count=ping_count, wifi_client=wifi_client,
                              protocol=protocol,
                              net_perf_client=net_perf_client,
                              traffic_type="RX")

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan_and_connect_from_remote",
            ble_pairing=1,
            conn_interval=4000,
        )
        ble_obj.advertise_dut()
        wlan_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_Coex_sdk_WLAN_IPV6_UDP_TX_BLE_20ms_C538023(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        net_perf_client,
        protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Advertise DUT
        4. Join the access point and get ipv6 address
        5. Enable wlan and bt power save mode in dut after the connection
        6. Scan from remote BLE device and connect to DUT with connection interval 20ms
        7. Start the iperf UDP server on the Remote device
        8. Start the iperf UDP client on the DUT
        9. Validate the throughput
        10.check BLE connection stability


    """

    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="iperf",
                              ping_count=ping_count, wifi_client=wifi_client,
                              protocol=protocol,
                              net_perf_client=net_perf_client,
                              traffic_type="TX")

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan_and_connect_from_remote",
            conn_interval=20,
        )
        ble_obj.advertise_dut()
        wlan_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_Coex_sdk_WLAN_IPV6_UDP_TX_BLE_112ms_C538024(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        net_perf_client,
        protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Advertise DUT
        4. Join the access point and get ipv6 address
        5. Enable wlan and bt power save mode in dut after the connection
        6. Scan from remote BLE device and connect to DUT with connection interval 112ms
        7. Start the iperf UDP server on the Remote device
        8. Start the iperf UDP client on the DUT
        9. Validate the throughput
        10.check BLE connection stability


    """

    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="iperf",
                              ping_count=ping_count, wifi_client=wifi_client,
                              protocol=protocol,
                              net_perf_client=net_perf_client,
                              traffic_type="TX")

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan_and_connect_from_remote",
            conn_interval=112,
            ble_pairing=1,
        )
        ble_obj.advertise_dut()
        wlan_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_Coex_sdk_WLAN_IPV6_UDP_TX_BLE_4000ms_C538025(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        net_perf_client,
        protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Advertise DUT
        4. Join the access point and get ipv6 address
        5. Enable wlan and bt power save mode in dut after the connection
        6. Scan from remote BLE device and connect to DUT with connection interval 4000ms
        7. Start the iperf UDP server on the Remote device
        8. Start the iperf UDP client on the DUT
        9. Validate the throughput
        10.check BLE connection stability


    """

    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="iperf",
                              ping_count=ping_count, wifi_client=wifi_client,
                              protocol=protocol,
                              net_perf_client=net_perf_client,
                              traffic_type="TX")

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan_and_connect_from_remote",
            conn_interval=4000,
            ble_pairing=1,
        )
        ble_obj.advertise_dut()
        wlan_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_Coex_sdk_WLAN_IPV6_UDP_TX_BLE_C538027(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        net_perf_client,
        protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security with IPV6 stateful
        3. Advertise DUT
        4. Join the access point and get ipv6 address
        5. Enable wlan and bt power save mode in dut after the connection
        6. Scan from remote BLE device and connect to DUT
        7. Start the iperf UDP server on the Remote device
        8. Start the iperf UDP client on the DUT
        9. Validate the throughput
        10.check BLE connection stability


    """

    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="iperf",
                              ping_count=ping_count, wifi_client=wifi_client,
                              protocol=protocol,
                              net_perf_client=net_perf_client,
                              traffic_type="TX",
                              timeout=60)
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notifications",
            dev_state=8,
            gatt=True,
            service_class=["HeartRateService"],
            ble_pairing=1,
        )

        ble_obj.check_scan_functionality()
        wlan_obj.join_to_ap()
        ble_obj.connect_from_dut()
        ble_obj.fetch_profiles()
        ble_obj.start()
        time.sleep(5)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
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
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA3", "passphrase": "1234567890", "ipv6_state": "0",
                               "protected_management_frame": "Capable",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4431")
@pytest.mark.http_server("raspi_lighttpd")
def test_Coex_sdk_ipv6_http_get_2048_url_BLE_adv_scan_C156989(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    index_path,
    http_server,
    http_client
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. scan& Join to the access point and enable the dhcp
        2. Advertise DUT ,Scan from remote device
        3. Advertise remote device & Scan from DUT
        4. Enable the wlan and bt power save mode
        5. Initiate ping from the dut

    """
    try:
        index_path = "url_exact_2048_bytes/" * 97 + "2048url.htm"
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_count=ping_count, wifi_client=wifi_client, addr_type="link",
                              http_server=http_server,
                              index_path=index_path,
                              http_client=http_client
                              )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="advertise",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        sl_collections.check_ble_scan_functionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_address=ble_obj.ble_dut_address,
            timeout=60,
        )
        for count in range(0, iter_count):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
        ble_client.interfaces.bluetooth.close()
        sl_collections.scan_from_remote_device(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_dut_address=ble_obj.ble_dut_address,
        )
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        ble_client.interfaces.bluetooth.stop_advertising()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_dut.interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                              | Si91xTCPIPFeatureBitMap.DHCPv6Server
                              | Si91xTCPIPFeatureBitMap.DHCPv6Client
                              | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                              | Si91xTCPIPFeatureBitMap.IPv6Mode,
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
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}}

    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": '1234567890'})
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
def test_Coex_sdk_WLAN_ipv6_tcp_tx_ble_tx_dle_100B_C538028(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        net_perf_client,
        protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on stateless WPA2 security
        3. Advertise DUT, Scan from remote device
        4. Initiate the connection from DUT to remote device in SMP mode
        5. Start the data transfer from remote device to DUT on DLE with 100 bytes
        6. Join the access point and get ipv6 address
        7. Enable wlan and bt power save mode in dut after the connection
        8. Initiate ping from the dut
        9. Do the TCP Tx from the AP backend machine to DUT's IPV6 Address
    """
    ble_dut_addr = ""
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"

        wifi_obj = WLanThread(
            wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
            test_name=test_name, sl_collections=sl_collections, test_type="iperf",
            ping_count=ping_count, wifi_client=wifi_client,
            protocol=protocol,
            net_perf_client=net_perf_client,
            traffic_type="TX"
        )
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
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
            periodic_delay=0,
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
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.memory_free(address2)
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        ble_obj.ble_disconnect()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        # bluetooth close
        ble_client.interfaces.bluetooth.close()
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        if ble_obj is not None:
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                              | Si91xTCPIPFeatureBitMap.DHCPv6Server
                              | Si91xTCPIPFeatureBitMap.DHCPv6Client
                              | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                              | Si91xTCPIPFeatureBitMap.IPv6Mode,
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
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}}

    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
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

def test_Coex_sdk_WLAN_ipv6_udp_tx_ble_tx_dle_240B_C538029(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut, ble_client,
        request, utf_constants, sl_collections,
        wifi_client,
        sniffer_filter,
        net_perf_client,
        protocol
):
    """
        Test Steps:
            1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
            2. Configure AP on stateless WPA2 security
            3. Advertise DUT, Scan from remote device
            4. Initiate the connection from DUT to remote device in SMP mode
            5. Start the data transfer from remote device to DUT on DLE with 240 bytes
            6. Join the access point and get ipv6 address
            7. Enable wlan and bt power save mode in dut after the connection
            8. Initiate ping from the dut
            9. Do the UDP Tx from the AP backend machine to DUT's IPV6 Address
        """
    ble_dut_addr = ""
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"

        wifi_obj = WLanThread(
            wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
            test_name=test_name, sl_collections=sl_collections, test_type="iperf",
            ping_count=ping_count, wifi_client=wifi_client,
            protocol=protocol,
            net_perf_client=net_perf_client,
            traffic_type="TX"
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
            periodic_delay=0,
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
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.memory_free(address2)
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        ble_obj.ble_disconnect()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        # bluetooth close
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)

# Skipping the test case as there is a known issue for HTTP download
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4429")
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        }
    }
)
@pytest.mark.config("wifi_dut", ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W)
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurrent_STA", "security": "WPA3", "passphrase": "12345678", "ipv6_state": "0", 'channel': 11}
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"10MB.htm"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
def test_Coex_sdk_WLAN_ipv6_http_download_BLE_adv_scan_C156993(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    index_path,
    http_server
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Scan and connect to the access point and enable the dhcp
        2. Advertise DUT and Scan from remote device
        3. Advertise remote device and Scan from DUT
        4. Enable the WLAN and BT power save mode
        5. Do the HTTP download

    """
    ble_obj = ''
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            test_type="http",
            http_server=http_server,
            index_path=index_path
        )

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="advertise",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        sl_collections.check_ble_scan_functionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_address=ble_obj.ble_dut_address,
            timeout=60,
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_client.interfaces.bluetooth.close()
        sl_collections.scan_from_remote_device(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_dut_address=ble_obj.ble_dut_address,
        )
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        ble_client.interfaces.bluetooth.stop_advertising()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


