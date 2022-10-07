import pytest

from utf.interfaces.iperf import IperfConstants
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116AsyncEventType, RS9116BTFeatureBitMap, RS9116PowerSaveProcedureTypes
from utf.utils.logger import get_logger
import time
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.iperf.iperf_utils import ping



def logger():
    return get_logger(__name__)


class Wlan:
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, http_server=None, index_path=None,
                 http_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.http_server = http_server
        self.http_client = http_client
        self.index_path = index_path
        self.device_address = {}

    def wlan_association(self, enable_sniffer=False, file_name=None):
        self.device_address = {}
        '''Function is responsible to associate with AP and return the device ip/mac address information'''
        if enable_sniffer:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            time.sleep(2)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)

        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)

        ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f'\n AP BSSID = {ap_bssid}')
        self.device_address['ap_bssid'] = ap_bssid

        self.wifi_dut.interfaces.wifi.start_ip()
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"\n DUT MAC Address: {dut_mac_address}")
        self.device_address['dut_mac_address'] = dut_mac_address

        dut_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"\n DUT ip address: {dut_ip}")
        self.device_address['dut_ip_address'] = dut_ip
        return self.device_address

    def http_download(self):
        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
        logger().info("This API used to get the http data from the server")
        status, content = self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)
        time.sleep(30)
        assert status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        logger().info(status)
        logger().info(content)
        assert content == content, f"http send and receive content is not same"

        logger().info(status)
        logger().info(content)

    def static_sync(self):
        ''' This function is responsible for series of test steps
        WLAN scan, connect, ipconfig, disconnect, HTTP download started
        :return:
        '''
        self.wlan_association()
        self.http_download()
        self.wifi_dut.interfaces.wifi.leave()
        self.wlan_association()


class DutBle:
    def __init__(self, wifi_dut=None, ble_dut=None):
        super().__init__()
        self.bt_dut_address = None
        self.ble_dut = ble_dut
        self.wifi_dut = wifi_dut

    def start(self):
        self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert self.bt_dut_address is not None
        logger().info(f"\n\n Start DUT BLE \n DUT BLE Address is {self.bt_dut_address}")

    def scan(self, bt_client_address=None, ble_scan_interval=256, timeout=10):
        logger().info("\n\n ***** start ble scan in DUT ***** \n\n")
        self.ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address,
                                                             ble_scan_interval=ble_scan_interval, timeout=timeout)

    def advertise(self, ble_adv_int_min=256, ble_adv_int_max=512, ble_adv_channel_map=7, timeout=10, ):
        logger().info("\n\n ***** start ble advertisement in DUT ***** \n\n")
        self.ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=ble_adv_int_min,
                                                                ble_adv_int_max=ble_adv_int_max, timeout=timeout)
        # self.ble_dut.interfaces.bluetooth.ble_start_advertising()

    def advertise_stop(self, timeout=10):
        logger().info("\n\n ***** stop ble advertisement in DUT ***** \n\n")
        self.ble_dut.interfaces.bluetooth.ble_stop_advertising(timeout=timeout)

    def connect(self, bt_client_address, ble_conn_interval_min=160, ble_conn_interval_max=160,
                ble_conn_latency=0,
                ble_supervision_timeout=2000, expected="RSI_BLE_ENCRYPT_STARTED_EVENT", timeout=10):
        logger().info(f"\n\n ***** DUT ble is trying to connect to client = {bt_client_address} ***** \n")
        self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address,
                                                  ble_conn_interval_min=ble_conn_interval_min,
                                                  ble_conn_interval_max=ble_conn_interval_max,
                                                  ble_conn_latency=ble_conn_latency,
                                                  ble_supervision_timeout=ble_supervision_timeout, expected=expected,
                                                  timeout=timeout)

    def disconnect(self, ble_remote_dev_address=None, timeout=10):
        logger().info(f"\n\n ***** DUT ble is trying to disconnect to client = {ble_remote_dev_address} ***** \n")
        self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_remote_dev_address, timeout=timeout)

    def scan_stop(self):
        logger().info("\n\n ***** stop ble scan in DUT ***** \n\n")
        self.ble_dut.interfaces.bluetooth.ble_stop_scanning()

    def add_service(self, uid_name: int = 0):
        logger().info(f"\n\n ***** Start ble service {uid_name} in DUT ***** \n\n")
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=uid_name)

    def add_characteristic(self, uid_name: int = 0):
        logger().info(f"\n\n ***** Start ble characteristic {uid_name} in DUT ***** \n\n")
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=uid_name)

    def get_state(self, verify_state=None):
        logger().info(f"\n\n ***** Get device state ***** \n\n")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        logger().info(f'STATE= {state}')
        state_int = int(state) if state.isdigit() else -1
        assert state_int == verify_state, "DUT is not connected to BLE"
        logger().info("DUT is not disconnected from BLE")


class RespiBle:
    def __init__(self, ble_client=None):
        super().__init__()
        self.ble_client = ble_client
        self.bt_client_address = None

    def advertise(self, bt_dut_address=None, smp_adv=False):
        logger().info(f"\n\n ***** Start RESPI BLE with advertisement *****\n\n")
        if smp_adv:
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address)
        else:
            self.bt_client_address = self.ble_client.interfaces.bluetooth.ble_start_advertising()
        assert self.bt_client_address is not None
        return self.bt_client_address

    def scan(self, bt_client_address=None):
        logger().info("\n\n ***** Start smp scan from the RESPI device *****\n\n")
        bt_remote_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_client_address)
        assert bt_remote_address, "failed to initiate ble in remote device"

    def scan_stop(self):
        logger().info("\n\n ***** stop scanning in RESPI....*****\n\n")
        self.ble_client.interfaces.bluetooth.stop_scanning()

    # def connect(self, ble_dut_address):
    #     logger().info("\n\n ***** RESPI is connecting with DUT ....*****\n\n")
    #     self.ble_client.interfaces.bluetooth.connect(ble_dut_address)

    def connect(self, bt_client_address=None, ble_conn_interval_min=None, ble_conn_interval_max=None,
                ble_conn_latency=None,
                ble_supervision_timeout=None, expected=None, timeout=None):
        logger().info(f"\n\n ***** DUT ble is trying to connect to client = {bt_client_address} ***** \n")
        self.ble_client.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address,
                                                         ble_conn_interval_min=ble_conn_interval_min,
                                                         ble_conn_interval_max=ble_conn_interval_max,
                                                         ble_conn_latency=ble_conn_latency,
                                                         ble_supervision_timeout=ble_supervision_timeout,
                                                         expected=expected,
                                                         timeout=timeout)

    def advertise_stop(self, timeout=10):
        logger().info(f"\n\n ***** Stop RESPI BLE advertisement *****\n\n")
        self.ble_client.interfaces.bluetooth.ble_stop_advertising(timeout=timeout)

    def disconnect(self, bt_device_address=None, timeout=10):
        logger().info(f"\n\n ***** Remote device is trying to disconnect to client = {bt_device_address} ***** \n")
        self.ble_client.interfaces.bluetooth.ble_disconnect(bt_device_address, timeout=timeout)


class WlanThread(ThreadBase):
    iterate_count = 0

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None, http_server=None,
                 index_path=None, iterate_count=None, http_client=None, https_server=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.test_case_no = test_case_no
        self.http_server = http_server
        self.https_server = https_server
        self.http_client = http_client
        self.index_path = index_path
        self.dut_obj = DutBle()
        self.count = 0
        self.iterate_count = iterate_count
        self.wlan_obj = Wlan(self.wifi_dut, self.wifi_access_point, self.wifi_sniffer, self.http_server,
                             self.index_path)

    def run(self):
        if self.test_case_no == 18959:
            logger().info(f'\n\n ***** Start WLAN scan ***** \n')
            self.wifi_dut.interfaces.wifi.scan(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                               channel=self.wifi_access_point.interfaces.wifi.channel)
        if self.test_case_no == 18961:
            self.wlan_obj.static_sync()

        if self.test_case_no == 18963:
            count = 0
            for i in range(0, self.iterate_count):
                logger().info(f'\n\n ***** Start Wi-Fi sync iteration {i} ***** \n')
                self.wlan_obj.static_sync()
                count = i
            WlanThread.iterate_count = WlanThread.iterate_count + count

        if self.test_case_no == 18964:
            self.wlan_obj.wlan_association()

        if self.test_case_no == 18972:
            count = 1
            for i in range(0, self.iterate_count+1):
                logger().info(f'\n\n ***** Start WLAN scan iteration {i} ***** \n')
                self.wifi_dut.interfaces.wifi.scan(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                   channel=self.wifi_access_point.interfaces.wifi.channel)
                count = i
            WlanThread.iterate_count = WlanThread.iterate_count + count

class BleThread(ThreadBase):
    def __init__(self, wifi_dut=None, ble_dut=None, ble_client=None, test_case_no=None, iterate_count=None,
                 ble_sniffer=None, utf_constants=None, ble_clients=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut = ble_dut
        self.dut_ble = DutBle(self.wifi_dut, self.ble_dut)
        self.respi_ble = RespiBle(self.ble_client)
        self.test_case_no = test_case_no
        self.iterate_count = iterate_count
        self.verify = False
        self.ble_sniffer = ble_sniffer
        self.utf_constants = utf_constants
        self.ble_clients = ble_clients

        if self.ble_clients:
            remote_devices_count = self.utf_constants.get("remote_devices_count")
            logger().info(f'\n\n ***** Total number of BLE clients in setup = {remote_devices_count}\n\n')
            if remote_devices_count == 2:
                self.ble_client1 = self.ble_clients[0]
                self.ble_client2 = self.ble_clients[1]

    def multi_client_connection_with_services_notify(self):
        """Note need to change service id as per test case requirement """
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        conn_params = {"min_conn_interval": 45,
                       "max_conn_interval": 45}
        data1 = "LzY0"

        logger().info(f'BLE CLIENTS = {self.ble_client1} \n {self.ble_client2}')

        remote_devices_count = self.utf_constants.get("remote_devices_count")
        logger().info(f'\n\n ***** Total number of BLE clients in setup = {remote_devices_count}\n\n')

        assert len(self.ble_clients) >= remote_devices_count

        logger().info("start ble in dut")
        self.dut_ble.start()

        '''Right these function are getting fail will uncomment when fix available'''
        self.dut_ble.add_service(uid_name=0x6E)
        self.dut_ble.add_characteristic(uid_name=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
        self.dut_ble.advertise()
        time.sleep(1)
        self.ble_client1.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(1)

        # Connect BLE client 1 to DUT
        self.ble_client1.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                 min_conn_interval=conn_params["min_conn_interval"],
                                                 max_conn_interval=conn_params["max_conn_interval"])

        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected

        time.sleep(1)
        self.dut_ble.advertise()
        time.sleep(1)
        self.ble_client2.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(1)

        # Connect BLE client 2 to DUT
        self.ble_client2.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                 min_conn_interval=conn_params["min_conn_interval"],
                                                 max_conn_interval=conn_params["max_conn_interval"])

        time.sleep(1)
        logger().info(f'\n\n Remote device will discover services and characteristic of DUT \n\n')

        # resolving characteristic
        bus = self.ble_client1.interfaces.bluetooth.bus
        logger().info(f'\n\n BUS = {bus} \n')
        services, chars = self.ble_client1.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        logger().info(f'\n\n Services ={services} \n chars = {chars}')
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char, char_props = self.ble_client1.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                                services=services,
                                                                                                service_uid=service_uid,
                                                                                                char_uid=char_uid)

        assert char is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        # read value - Notifications not enabled
        result = self.ble_client1.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data1

        # subscribe to notifications
        self.ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                 char_uid=char_uid)

        # notify only
        self.wifi_dut.interfaces.wifi.ble_notify_value()

        logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')

        # resolving characteristic
        bus = self.ble_client2.interfaces.bluetooth.bus
        logger().info(f'\n\n BUS = {bus} \n')
        services, chars = self.ble_client2.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        logger().info(f'\n\n Services ={services} \n chars = {chars}')
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char, char_props = self.ble_client2.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                                services=services,
                                                                                                service_uid=
                                                                                                service_uid,
                                                                                                char_uid=char_uid)

        assert char is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        # read value - Notifications not enabled
        result = self.ble_client2.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data1

        # subscribe to notifications
        self.ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                 char_uid=char_uid)

        # notify only
        self.wifi_dut.interfaces.wifi.ble_notify_value()

    def multi_client_connection_disconnection_with_services_notify(self):
        """Note need to change service id as per test case requirement """
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        conn_params = {"min_conn_interval": 45,
                       "max_conn_interval": 45}

        conn_params1 = {"min_conn_interval": 500,
                       "max_conn_interval": 500}

        data1 = "LzY0"

        logger().info(f'BLE CLIENTS = {self.ble_client1} \n {self.ble_client2}')

        remote_devices_count = self.utf_constants.get("remote_devices_count")
        logger().info(f'\n\n ***** Total number of BLE clients in setup = {remote_devices_count}\n\n')

        assert len(self.ble_clients) >= remote_devices_count

        logger().info("start ble in dut")
        self.dut_ble.start()

        '''Right now these function are getting fail will uncomment when fix available'''
        self.dut_ble.add_service(uid_name=0x6E)
        self.dut_ble.add_characteristic(uid_name=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
        self.dut_ble.scan(ble_scan_interval=53)
        time.sleep(1)
        self.dut_ble.advertise()
        time.sleep(1)
        self.ble_client1.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(1)

        # Connect BLE client 1 to DUT
        self.ble_client1.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                 min_conn_interval=conn_params["min_conn_interval"],
                                                 max_conn_interval=conn_params["max_conn_interval"])

        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected

        time.sleep(1)
        self.dut_ble.advertise()
        time.sleep(1)
        self.ble_client2.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(1)

        # Connect BLE client 2 to DUT
        self.ble_client2.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                 min_conn_interval=conn_params1["min_conn_interval"],
                                                 max_conn_interval=conn_params1["max_conn_interval"])

        time.sleep(1)
        logger().info(f'\n\n Remote device will discover services and characteristic of DUT \n\n')

        # resolving characteristic
        bus = self.ble_client1.interfaces.bluetooth.bus
        logger().info(f'\n\n BUS = {bus} \n')
        services, chars = self.ble_client1.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        logger().info(f'\n\n Services ={services} \n chars = {chars}')
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char, char_props = self.ble_client1.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                                services=services,
                                                                                                service_uid=service_uid,
                                                                                                char_uid=char_uid)

        assert char is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        # read value - Notifications not enabled
        result = self.ble_client1.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data1

        # subscribe to notifications
        self.ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                 char_uid=char_uid)

        # notify only
        self.wifi_dut.interfaces.wifi.ble_notify_value()

        logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')

        # resolving characteristic
        bus = self.ble_client2.interfaces.bluetooth.bus
        logger().info(f'\n\n BUS = {bus} \n')
        services, chars = self.ble_client2.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        logger().info(f'\n\n Services ={services} \n chars = {chars}')
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char, char_props = self.ble_client2.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                                services=services,
                                                                                                service_uid=
                                                                                                service_uid,
                                                                                                char_uid=char_uid)

        assert char is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        # read value - Notifications not enabled
        result = self.ble_client2.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data1

        # subscribe to notifications
        self.ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                 char_uid=char_uid)

        # notify only
        self.wifi_dut.interfaces.wifi.ble_notify_value()
        time.sleep(1)
        self.dut_ble.scan()
        time.sleep(1)
        self.ble_client1.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)
        self.ble_client2.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)

        # Again trying to connect the DUT
        self.dut_ble.advertise()
        time.sleep(1)
        self.ble_client1.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(1)

        # Connect BLE client 1 to DUT
        self.ble_client1.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address)

        self.dut_ble.advertise()
        time.sleep(1)
        self.ble_client2.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(1)

        # Connect BLE client 2 to DUT
        self.ble_client2.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address)

    def multi_client_connection_with_different_connection_intervals(self):
        """Note need to change service id as per test case requirement """
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        conn_params = {"min_conn_interval": 45,
                       "max_conn_interval": 45}

        conn_params1 = {"min_conn_interval": 500,
                       "max_conn_interval": 500}

        data1 = "LzY0"

        logger().info(f'BLE CLIENTS = {self.ble_client1} \n {self.ble_client2}')

        remote_devices_count = self.utf_constants.get("remote_devices_count")
        logger().info(f'\n\n ***** Total number of BLE clients in setup = {remote_devices_count}\n\n')

        assert len(self.ble_clients) >= remote_devices_count

        logger().info("start ble in dut")
        self.dut_ble.start()

        '''Right now these function are getting fail will uncomment when fix available'''
        self.dut_ble.add_service(uid_name=0x6E)
        self.dut_ble.add_characteristic(uid_name=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
        self.dut_ble.scan(ble_scan_interval=53)
        time.sleep(1)
        self.dut_ble.advertise()
        time.sleep(1)
        self.ble_client1.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(1)

        # Connect BLE client 1 to DUT
        self.ble_client1.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                 min_conn_interval=conn_params["min_conn_interval"],
                                                 max_conn_interval=conn_params["max_conn_interval"])

        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected

        time.sleep(1)
        self.dut_ble.advertise()
        time.sleep(1)
        self.ble_client2.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(1)

        # Connect BLE client 2 to DUT
        self.ble_client2.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                 min_conn_interval=conn_params1["min_conn_interval"],
                                                 max_conn_interval=conn_params1["max_conn_interval"])

        time.sleep(1)
        logger().info(f'\n\n Remote device will discover services and characteristic of DUT \n\n')

        # resolving characteristic
        bus = self.ble_client1.interfaces.bluetooth.bus
        logger().info(f'\n\n BUS = {bus} \n')
        services, chars = self.ble_client1.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        logger().info(f'\n\n Services ={services} \n chars = {chars}')
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char, char_props = self.ble_client1.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                                services=services,
                                                                                                service_uid=service_uid,
                                                                                                char_uid=char_uid)

        assert char is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        # read value - Notifications not enabled
        result = self.ble_client1.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data1

        # subscribe to notifications
        self.ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                 char_uid=char_uid)

        # notify only
        self.wifi_dut.interfaces.wifi.ble_notify_value()

        logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')

        # resolving characteristic
        bus = self.ble_client2.interfaces.bluetooth.bus
        logger().info(f'\n\n BUS = {bus} \n')
        services, chars = self.ble_client2.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        logger().info(f'\n\n Services ={services} \n chars = {chars}')
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char, char_props = self.ble_client2.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                                services=services,
                                                                                                service_uid=
                                                                                                service_uid,
                                                                                                char_uid=char_uid)

        assert char is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        # read value - Notifications not enabled
        result = self.ble_client2.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data1

        # subscribe to notifications
        self.ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                 char_uid=char_uid)

        # notify only
        self.wifi_dut.interfaces.wifi.ble_notify_value()

        '''Change connection parameters High(11.25-15ms), Balanced(30-50ms), Low power(100-125ms) and check whether 
            this modification causing any BLE disconnection'''

        # Update connection Interval for second remote device
        self.ble_client1.interfaces.bluetooth.ble_conn_params_update(self.dut_ble.bt_dut_address, min_int=15,
                                                                     max_int=15, timeout=500)
        time.sleep(1)
        self.ble_client1.interfaces.bluetooth.ble_conn_params_update(self.dut_ble.bt_dut_address, min_int=40,
                                                                     max_int=40, timeout=500)
        time.sleep(1)
        self.ble_client1.interfaces.bluetooth.ble_conn_params_update(self.dut_ble.bt_dut_address, min_int=112.5,
                                                                     max_int=112.5, timeout=500)

        # Update connection Interval for second remote device
        self.ble_client2.interfaces.bluetooth.ble_conn_params_update(self.dut_ble.bt_dut_address, min_int=15,
                                                                     max_int=15, timeout=500)
        time.sleep(1)
        self.ble_client2.interfaces.bluetooth.ble_conn_params_update(self.dut_ble.bt_dut_address, min_int=40,
                                                                     max_int=40, timeout=500)
        time.sleep(1)
        self.ble_client2.interfaces.bluetooth.ble_conn_params_update(self.dut_ble.bt_dut_address, min_int=112.5,
                                                                     max_int=112.5, timeout=500)


    def multi_client_connection_3_with_services_notify(self):
        """Note need to change service id as per test case requirement """
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

        data1 = "LzY0"

        logger().info("start ble in dut")
        self.dut_ble.start()

        '''Right these function are getting fail will uncomment when fix available'''
        self.dut_ble.add_service(uid_name=0x6E)
        self.dut_ble.add_characteristic(uid_name=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
        time.sleep(1)
        self.dut_ble.scan(ble_scan_interval=53)
        time.sleep(1)
        self.dut_ble.advertise()
        time.sleep(1)

        # Start connection between DUT & RESPI 1 client
        ble1_client_address = self.ble_client1.interfaces.bluetooth.start_smp_adv(self.dut_ble.bt_dut_address)
        assert ble1_client_address, "Unable to get ble_client_address"
        time.sleep(1)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble1_client_address, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("Initiating BLE connection with ble_client")
        self.dut_ble.connect(bt_client_address=ble1_client_address, ble_conn_interval_min=300, ble_conn_interval_max=300)
        # self.dut_ble.connect(ble1_client_address)
        logger().info("BLE Connection success")
        time.sleep(1)

        # Start connection between DUT & RESPI 2 client
        ble2_client_address = self.ble_client2.interfaces.bluetooth.start_smp_adv(self.dut_ble.bt_dut_address)
        assert ble2_client_address, "Unable to get ble_client_address"
        time.sleep(1)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble2_client_address, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("Initiating BLE connection with ble_client")
        self.dut_ble.connect(bt_client_address=ble2_client_address, ble_conn_interval_min=300, ble_conn_interval_max=300)
        # self.dut_ble.connect(ble2_client_address)
        logger().info("BLE Connection success")
        time.sleep(1)

        # Start connection between DUT & RESPI 3 client
        ble3_client_address = self.ble_client3.interfaces.bluetooth.start_smp_adv(self.dut_ble.bt_dut_address)
        assert ble3_client_address, "Unable to get ble_client_address"
        time.sleep(1)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble3_client_address, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("Initiating BLE connection with ble_client")
        self.dut_ble.connect(bt_client_address=ble3_client_address, ble_conn_interval_min=300, ble_conn_interval_max=300)
        # self.dut_ble.connect(ble2_client_address)
        logger().info("BLE Connection success")
        time.sleep(1)

        # resolving characteristic
        bus = self.ble_client1.interfaces.bluetooth.bus
        logger().info(f'\n\n BUS = {bus} \n')
        services, chars = self.ble_client1.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        logger().info(f'\n\n Services ={services} \n chars = {chars}')
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char, char_props = self.ble_client1.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                                services=services,
                                                                                                service_uid=service_uid,
                                                                                                char_uid=char_uid)

        assert char is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        # read value - Notifications not enabled
        result = self.ble_client1.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data1

        # subscribe to notifications
        self.ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                 char_uid=char_uid)

        # notify only
        self.wifi_dut.interfaces.wifi.ble_notify_value()

        logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')

        # resolving characteristic
        bus = self.ble_client2.interfaces.bluetooth.bus
        logger().info(f'\n\n BUS = {bus} \n')
        services, chars = self.ble_client2.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        logger().info(f'\n\n Services ={services} \n chars = {chars}')
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char, char_props = self.ble_client2.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                                services=services,
                                                                                                service_uid=
                                                                                                service_uid,
                                                                                                char_uid=char_uid)

        assert char is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        # read value - Notifications not enabled
        result = self.ble_client2.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data1

        # subscribe to notifications
        self.ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                 char_uid=char_uid)

        # notify only
        self.wifi_dut.interfaces.wifi.ble_notify_value()

    def run(self):
        if self.test_case_no == 18959:
            self.dut_ble.start()
            self.dut_ble.advertise()

            time.sleep(5)
            self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)
            self.respi_ble.scan_stop()

        if self.test_case_no == 18960:
            self.dut_ble.start()
            self.dut_ble.scan(timeout=120)

        if self.test_case_no == 18963:
            '''JIRA filed for SMP error'''
            # Commented code are right will use when JIRA resolved
            # if self.verify:
            #     self.dut_ble.connect(self.respi_ble.bt_client_address)
            # else:
            #     self.dut_ble.start()
            #     self.dut_ble.add_service(uid_name=0x180D)
            #     self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address, smp_adv=True)
            #     self.dut_ble.scan(bt_client_address=self.respi_ble.bt_client_address, timeout=120)
            #
            #     self.dut_ble.connect(self.respi_ble.bt_client_address)
            #     # time.sleep(5)
            #     while 1:
            #         if WlanThread.iterate_count == self.iterate_count - 1:
            #             logger().info(f'ITERATE COUNT = {WlanThread.iterate_count}')
            #             self.dut_ble.disconnect(ble_remote_dev_address=self.respi_ble.bt_client_address)
            #             self.verify = True
            #             break
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address, smp_adv=True)
            self.dut_ble.scan(bt_client_address=self.respi_ble.bt_client_address, timeout=120)
            self.dut_ble.connect(self.respi_ble.bt_client_address)
            time.sleep(5)
            self.dut_ble.disconnect(ble_remote_dev_address=self.respi_ble.bt_client_address)
            time.sleep(5)
            # self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address, smp_adv=True)
            # self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address, smp_adv=True)
            self.dut_ble.connect(self.respi_ble.bt_client_address)

        if self.test_case_no == 18964:
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address, smp_adv=True)
            self.dut_ble.scan(bt_client_address=self.respi_ble.bt_client_address, timeout=120)

        if self.test_case_no == 18972:
            self.dut_ble.start()
            self.dut_ble.advertise(ble_adv_int_min=int(211.25), ble_adv_int_max=int(211.25), timeout=30)
            while 1:
                if WlanThread.iterate_count == self.iterate_count - 1:
                    logger().info(f'ITERATE COUNT = {WlanThread.iterate_count}')
                    self.dut_ble.advertise_stop()
                    break

        if self.test_case_no == 18974:
            ble_scan_interval = 33
            ble_scan_interval_value = int(ble_scan_interval / 0.625)
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address, smp_adv=True)
            time.sleep(2)

            self.ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=self.respi_ble.bt_client_address,
                                                                 ble_scan_interval=ble_scan_interval_value, timeout=120)

            # self.dut_ble.scan(bt_client_address=self.respi_ble.bt_client_address, ble_scan_interval=33, timeout=120)
            # while 1:
            #     if WlanThread.iterate_count == self.iterate_count - 1:
            #         logger().info(f'ITERATE COUNT = {WlanThread.iterate_count}')
            #         self.dut_ble.scan_stop()
            #         break

        if self.test_case_no == 18978:
            self.dut_ble.start()
            self.dut_ble.advertise(ble_adv_int_min=int(211.25), ble_adv_int_max=int(211.25), timeout=30)
            self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)

            while 1:
                if WlanThread.iterate_count == self.iterate_count - 1:
                    logger().info(f'ITERATE COUNT = {WlanThread.iterate_count}')
                    self.dut_ble.advertise_stop()
                    self.respi_ble.scan_stop()
                    break

        if self.test_case_no == 18980:
            ble_scan_interval = 256
            '''Need to add BLE scan interval JIRA filed'''
            # ble_scan_interval_value = int(ble_scan_interval / 0.625)
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address, smp_adv=True)
            self.dut_ble.scan(bt_client_address=self.respi_ble.bt_client_address, timeout=120)
            # self.dut_ble.scan(bt_client_address=self.respi_ble.bt_client_address, ble_scan_interval=ble_scan_interval_value, timeout=120)

            while 1:
                if WlanThread.iterate_count == self.iterate_count - 1:
                    logger().info(f'ITERATE COUNT = {WlanThread.iterate_count}')
                    self.dut_ble.scan_stop()
                    break

        if self.test_case_no == 18988:
            conn_params = {"min_conn_interval": 45,
                           "max_conn_interval": 45,
                           "conn_latency": 0,
                           "supervision_timeout": 800}
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.dut_ble.advertise()
            self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address, smp_adv=True)
            self.dut_ble.scan(bt_client_address=self.respi_ble.bt_client_address, timeout=120)
            self.dut_ble.connect(self.respi_ble.bt_client_address)
            self.dut_ble.get_state(verify_state=BLEDeviceState.Connected)

            time.sleep(10)
            self.ble_client.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                         min_conn_interval=conn_params["min_conn_interval"],
                                                         max_conn_interval=conn_params["max_conn_interval"],
                                                         conn_latency=conn_params["conn_latency"],
                                                         supervision_timeout=conn_params["supervision_timeout"])

            '''Need to add 20 bytes data transfer, Ravi will update on this'''

            time.sleep(300)
            while 1:
                if WlanThread.iterate_count == self.iterate_count - 1:
                    logger().info(f'ITERATE COUNT = {WlanThread.iterate_count}')
                    self.dut_ble.disconnect(ble_remote_dev_address=self.respi_ble.bt_client_address)
                    break

        if self.test_case_no == 18984:
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.dut_ble.advertise()

            # time.sleep(5)
            self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)
            time.sleep(2)
            logger().info("Initiating BLE connection")
            self.respi_ble.connect(self.dut_ble.bt_dut_address)
            # self.ble_client.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address)
            logger().info("BLE Connection success")
            time.sleep(5)

            # setting data length on ble_client
            with BleLogs(start_collecting_logs=True,
                         bt_log_path=f"reports/test_sta_ble_c18984.log_{int(time.time())}"):
                logger().info("Updating ble connection with connection parameters")
                self.ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                    dev_addr=self.dut_ble.bt_dut_address,
                    connection_handle="0x08 0x0013",
                    connection_interval_min="0x46 0x00",
                    connection_interval_max="0xA0 0x00",
                    max_latency="0xA0 0x00",
                    supervision_timeout="0x00 0x00",
                    min_ce_length="0x80 0x0c",
                    max_ce_length="0x00 0x00"
                )
            # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
            # time.sleep(300)
            # self.dut_ble.get_state(verify_state=BLEDeviceState.Connected)

        if self.test_case_no == 18985:
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.dut_ble.advertise()

            # time.sleep(5)
            self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)
            time.sleep(2)
            logger().info("Initiating BLE connection")
            self.respi_ble.connect(self.dut_ble.bt_dut_address)
            logger().info("BLE Connection success")
            time.sleep(5)

            # setting data length on ble_client
            with BleLogs(start_collecting_logs=True,
                         bt_log_path=f"reports/test_sta_ble_c18985.log_{int(time.time())}"):
                logger().info("Updating ble connection with connection parameters")
                self.ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                    dev_addr=self.dut_ble.bt_dut_address,
                    connection_handle="0x08 0x0013",
                    connection_interval_min="0x46 0x00",
                    connection_interval_max="0xA0 0x00",
                    max_latency="0xA0 0x00",
                    supervision_timeout="0x00 0x04",
                    min_ce_length="0x80 0x0c",
                    max_ce_length="0x00 0x00"
                )

        if self.test_case_no == 18986:
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.dut_ble.advertise()

            # time.sleep(5)
            self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)
            time.sleep(2)
            logger().info("Initiating BLE connection")
            self.respi_ble.connect(self.dut_ble.bt_dut_address)
            logger().info("BLE Connection success")
            time.sleep(5)

            # setting data length on ble_client
            with BleLogs(start_collecting_logs=True,
                         bt_log_path=f"reports/test_sta_ble_c18986.log_{int(time.time())}"):
                logger().info("Updating ble connection with connection parameters")
                self.ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                    dev_addr=self.dut_ble.bt_dut_address,
                    connection_handle="0x08 0x0013",
                    connection_interval_min="0x46 0x00",
                    connection_interval_max="0xA0 0x00",
                    max_latency="0xA0 0x00",
                    supervision_timeout="0x00 0x00",
                    min_ce_length="0x80 0x0c",
                    max_ce_length="0x00 0x00"
                )

        if self.test_case_no == 18987:
            file_name = 'ble_sniffer_18987'
            self.ble_sniffer.interfaces.sniffer.init_sniffer()
            self.ble_sniffer.interfaces.sniffer.start_capture(capture_file=file_name)

            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.dut_ble.advertise()

            # time.sleep(5)
            self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)
            time.sleep(2)
            logger().info("Initiating BLE connection")
            self.respi_ble.connect(self.dut_ble.bt_dut_address)
            logger().info("BLE Connection success")
            time.sleep(5)

            # setting data length on ble_client
            with BleLogs(start_collecting_logs=True,
                         bt_log_path=f"reports/test_wlan_sync_1mb_file_ble_slave_latency_c18987.log_{int(time.time())}"):
                logger().info("Updating ble connection with connection parameters")
                self.ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                    dev_addr=self.dut_ble.bt_dut_address,
                    connection_handle="0x08 0x0013",
                    connection_interval_min="0x46 0x00",
                    connection_interval_max="0xA0 0x00",
                    max_latency="0xA0 0x00",
                    supervision_timeout="0x00 0x00",
                    min_ce_length="0x80 0x0c",
                    max_ce_length="0x00 0x00"
                )

            self.ble_sniffer.interfaces.sniffer.stop_capture()
            time.sleep(5)
            self.ble_sniffer.interfaces.sniffer.start_capture()

            '''Need more clarification from manual POC to how to add sniffer validation '''
            with BleLogs(start_collecting_logs=True,
                         bt_log_path=f"reports/test_wlan_sync_1mb_file_ble_slave_latency_c18987_{int(time.time())}"):
                logger().info("Updating ble connection with connection parameters")
                self.ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                    dev_addr=self.dut_ble.bt_dut_address,
                    connection_handle="0x08 0x0013",
                    connection_interval_min="0x46 0x00",
                    connection_interval_max="0xA0 0x00",
                    max_latency="0xA0 0x00",
                    supervision_timeout="0x00 0x04",
                    min_ce_length="0x80 0x0c",
                    max_ce_length="0x00 0x00"
                )

            self.ble_sniffer.interfaces.sniffer.stop_capture()

        if self.test_case_no == 18971:
            self.multi_client_connection_with_services_notify()
            while 1:
                if WlanThread.iterate_count == self.iterate_count - 1:
                    logger().info(f'ITERATE COUNT = {WlanThread.iterate_count}')
                    self.dut_ble.advertise_stop()
                    self.ble_client1.interfaces.bluetooth.stop_scanning()
                    self.ble_client2.interfaces.bluetooth.stop_scanning()
                    break

        if self.test_case_no == 18973:
            self.multi_client_connection_disconnection_with_services_notify()
            while 1:
                if WlanThread.iterate_count == self.iterate_count - 1:
                    logger().info(f'ITERATE COUNT = {WlanThread.iterate_count}')
                    self.dut_ble.advertise_stop()
                    self.ble_client1.interfaces.bluetooth.stop_scanning()
                    self.ble_client2.interfaces.bluetooth.stop_scanning()
                    break

        if self.test_case_no == 18975:
            self.multi_client_connection_with_different_connection_intervals()
            while 1:
                if WlanThread.iterate_count == self.iterate_count - 1:
                    logger().info(f'ITERATE COUNT = {WlanThread.iterate_count}')
                    self.dut_ble.advertise_stop()
                    self.ble_client1.interfaces.bluetooth.stop_scanning()
                    self.ble_client2.interfaces.bluetooth.stop_scanning()
                    break

        if self.test_case_no == 18976:
            self.multi_client_connection_3_with_services_notify()
            while 1:
                if WlanThread.iterate_count == self.iterate_count:
                    logger().info(f'ITERATE COUNT = {WlanThread.iterate_count}')
                    self.dut_ble.scan_stop()
                    self.ble_client1.interfaces.bluetooth.stop_advertising()
                    self.ble_client2.interfaces.bluetooth.stop_advertising()
                    self.ble_client3.interfaces.bluetooth.stop_advertising()
                    break

        if self.test_case_no == 18982:
            self.multi_client_connection_3_with_services_notify()
            while 1:
                if WlanThread.iterate_count == self.iterate_count:
                    logger().info(f'ITERATE COUNT = {WlanThread.iterate_count}')
                    self.dut_ble.scan_stop()
                    self.ble_client1.interfaces.bluetooth.stop_advertising()
                    self.ble_client2.interfaces.bluetooth.stop_advertising()
                    self.ble_client3.interfaces.bluetooth.stop_advertising()
                    break

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_wlan_scan_dut_ble_adv_repi_scan_c18959(wifi_dut, wifi_access_point, ble_dut, ble_client):
    test_case_no = 18959
    '''Test DUT BLE advertisement + Remote BLE scan and Wi-Fi scan'''

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no)

    wlan_obj.start()
    ble_obj.start()
    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_wlan_ble_scan_c18960(wifi_dut, wifi_access_point, ble_dut, ble_client):
    test_case_no = 18960
    '''Test BLE scan and Wi-Fi scan'''
    '''This test case will be failed in shield box '''

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18959)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, test_case_no=test_case_no)

    wlan_obj.start()
    ble_obj.start()
    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_wlan_sync_ble_reconnection_c18963(wifi_dut, wifi_access_point, ble_dut, ble_client, http_server):
    test_case_no = 18963
    iterate_count = 5
    '''JIRA filed https://jira.silabs.com/browse/WIFI_BT_UTFHELP-1067'''
    '''Wi-Fi sync(transient) + 1 BLE phone connection and reconnection'''
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat is True
    logger().info(f'http server state is {server_stat}')

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no,
                          iterate_count=iterate_count, http_server=http_server)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                        iterate_count=iterate_count)

    # wlan_obj.start()
    ble_obj.start()
    ble_obj.wait_for_exit()
    # wlan_obj.wait_for_exit()
    # time.sleep(10)
    # wlan_obj.start()
    # ble_obj.start()
    # ble_obj.wait_for_exit()
    # wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_wlan_connect_ble_scan_c18964(wifi_dut, wifi_access_point, ble_dut, ble_client):
    test_case_no = 18964
    '''WIFI Connected and BLE scan'''

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no)

    wlan_obj.start()
    ble_obj.start()
    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_wlan_scan_ble_advertise_c18972(wifi_dut, wifi_access_point, ble_dut, ble_client):
    test_case_no = 18972
    iterate_count = 50
    '''WiFi Scan Coex Static Test with BLE advertise'''

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no,
                          iterate_count=iterate_count)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                        iterate_count=iterate_count)

    wlan_obj.start()
    ble_obj.start()
    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()
    wlan_obj.start()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_wlan_scan_ble_advertise_c18974(wifi_dut, wifi_access_point, ble_dut, ble_client):
    test_case_no = 18974
    iterate_count = 5
    '''https://jira.silabs.com/browse/WIFI_BT_UTFHELP-1093'''
    '''WiFi Scan Coex Static Test while BLE scan'''

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no,
                          iterate_count=72)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                        iterate_count=iterate_count)

    # wlan_obj.start()
    ble_obj.start()
    ble_obj.wait_for_exit()
    # wlan_obj.wait_for_exit()
    # wlan_obj.start()
    # wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_wlan_sync_ble_advertise_c18978(wifi_dut, wifi_access_point, ble_dut, ble_client, http_server):
    test_case_no = 18978
    iterate_count = 10
    '''WiFi Sync Coex Static Test while BLE advertise'''
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat is True
    logger().info(f'http server state is {server_stat}')

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                          iterate_count=iterate_count, http_server=http_server)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                        iterate_count=iterate_count)

    wlan_obj.start()
    ble_obj.start()
    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_wlan_sync_ble_scan_c18980(wifi_dut, wifi_access_point, ble_dut, ble_client, http_server):
    test_case_no = 18980
    iterate_count = 10
    '''WiFi Sync Coex Static Test while BLE scan'''
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat is True
    logger().info(f'http server state is {server_stat}')

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                          iterate_count=iterate_count, http_server=http_server)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                        iterate_count=iterate_count)

    wlan_obj.start()
    ble_obj.start()
    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()
    wlan_obj.start()
    wlan_obj.wait_for_exit()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
def test_wlan_sync_ble_stability_scan_c18988(wifi_dut, wifi_access_point, ble_dut, ble_client, http_server):
    test_case_no = 18988
    iterate_count = 2
    '''Test BLE phone connection stability while Wi-Fi sync when BLE device is connected first'''

    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat is True
    logger().info(f'http server state is {server_stat}')

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                          iterate_count=iterate_count, http_server=http_server)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                        iterate_count=iterate_count)

    ble_obj.start()
    # wlan_obj.start()
    ble_obj.wait_for_exit()
    # wlan_obj.wait_for_exit()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_ble_slave_latency_c18984(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client, index_path,
                                            http_server):
    test_case_no = 18984
    iterate_count = 2
    '''Verify Slave latency functionality when remote master update connection params with 0 slave latency while 1MB
 file download through HTTP'''
    '''Issue https://stash.silabs.com/projects/UTF/repos/utf_core/pull-requests/197/overview'''

    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat is True
    logger().info(f'http server state is {server_stat}')

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                          iterate_count=iterate_count, http_server=http_server)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                        iterate_count=iterate_count)

    ble_obj.start()
    wlan_obj.start()
    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_1mb_file_ble_slave_latency_c18985(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client,
                                                     index_path,
                                                     http_server):
    test_case_no = 18985
    iterate_count = 1
    '''Verify Slave latency functionality when remote master update connection params with slave latency field with 
    values between 1 to ((LSTO / (CIMax*2)) -1) while 1MB file download through HTTP'''
    '''Issue https://stash.silabs.com/projects/UTF/repos/utf_core/pull-requests/197/overview'''

    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat is True
    logger().info(f'http server state is {server_stat}')

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                          iterate_count=iterate_count, http_server=http_server)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                        iterate_count=iterate_count)

    ble_obj.start()
    wlan_obj.start()
    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()


@pytest.mark.rf_attenuator('50pa500_attenuator')
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"10MB.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_10mb_file_ble_slave_latency_c18986(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client,
                                                      index_path, http_server, rf_attenuator):
    test_case_no = 18986
    iterate_count = 1
    '''Verify Slave latency functionality when remote master update connection params with slave latency field out of 
    the range while 10MB file download through HTTP '''

    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat is True
    logger().info(f'http server state is {server_stat}')

    # Adding attenuator field to make it out of range
    wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator)

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                          iterate_count=iterate_count, http_server=http_server)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no)

    ble_obj.start()
    wlan_obj.start()
    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient |
                          RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_1mb_file_ble_slave_latency_c18987(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client,
                                                     index_path, http_server):
    test_case_no = 18987
    iterate_count = 1
    '''Verify Slave latency functionality when remote master update connection params with slave latency field with 
    values between 1 to ((LSTO / (CIMax*2)) -1) while 1MB file download through HTTP'''
    '''Issue https://stash.silabs.com/projects/UTF/repos/utf_core/pull-requests/197/overview'''

    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat is True
    logger().info(f'http server state is {server_stat}')

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                          iterate_count=iterate_count, http_server=http_server)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no)

    # ble_obj.start()
    wlan_obj.start()
    # ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_scan_ble_2_connection_c18971(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client, ble_clients, utf_constants):
    test_case_no = 18971
    iterate_count = 50
    '''WiFi Scan Coex Static connection test with 2 phones'''

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18972,
                          iterate_count=iterate_count)
    ble_obj = BleThread(wifi_dut=wifi_dut, test_case_no=test_case_no, ble_clients=ble_clients, utf_constants=utf_constants)

    wlan_obj.start()
    ble_obj.start()
    wlan_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    wlan_obj.start()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_scan_ble_2_connection_c18973(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client, ble_clients, utf_constants):
    test_case_no = 18973
    iterate_count = 50
    '''WiFi Scan Coex transient test with two BLE phones connection'''

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18972,
                          iterate_count=iterate_count)
    ble_obj = BleThread(wifi_dut=wifi_dut, test_case_no=test_case_no, ble_clients=ble_clients, utf_constants=utf_constants)

    wlan_obj.start()
    ble_obj.start()
    wlan_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    wlan_obj.start()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_scan_ble_2_connection_c18975(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client, ble_clients, utf_constants):
    test_case_no = 18975
    iterate_count = 50
    '''WiFi Scan Coex Static Test while BLE phones conn update'''

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18972,
                          iterate_count=iterate_count)
    ble_obj = BleThread(wifi_dut=wifi_dut, test_case_no=test_case_no, ble_clients=ble_clients, utf_constants=utf_constants)

    wlan_obj.start()
    ble_obj.start()
    wlan_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    wlan_obj.start()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient |
                          RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_static_ble_2_connection_c18977(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients, index_path, http_server, utf_constants):
    iterate_count = 10
    '''WiFi Sync Coex Static Test while 2 BLE connections'''

    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat is True
    logger().info(f'http server state is {server_stat}')

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                          iterate_count=iterate_count)
    ble_obj = BleThread(wifi_dut=wifi_dut, test_case_no=18971, ble_clients=ble_clients, utf_constants=utf_constants)

    wlan_obj.start()
    ble_obj.start()
    wlan_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    wlan_obj.start()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient |
                          RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_transient_sync_ble_2_connection_c18979(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients, index_path, http_server, utf_constants):
    iterate_count = 10
    '''WiFi Sync Coex transient test while 2 remote central connections'''

    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat is True
    logger().info(f'http server state is {server_stat}')

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                          iterate_count=iterate_count)
    ble_obj = BleThread(wifi_dut=wifi_dut, test_case_no=18973, ble_clients=ble_clients, utf_constants=utf_constants)

    wlan_obj.start()
    ble_obj.start()
    wlan_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    wlan_obj.start()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient |
                          RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_static_sync_ble_2_connection_c18981(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients, index_path, http_server, utf_constants):
    iterate_count = 10
    '''WiFi Sync Coex Static Test while two BLE phones conn params update'''

    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat is True
    logger().info(f'http server state is {server_stat}')

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                          iterate_count=iterate_count)
    ble_obj = BleThread(wifi_dut=wifi_dut, test_case_no=18975, ble_dut=ble_dut, ble_client=ble_client, ble_clients=ble_clients, utf_constants=utf_constants)

    wlan_obj.start()
    ble_obj.start()
    wlan_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    wlan_obj.start()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_scan_ble_3_connection_c18976(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client, ble_clients, utf_constants):
    test_case_no = 18976
    iterate_count = 5
    '''WiFi Scan Coex Static Test while 3 phone connections'''

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18972,
                          iterate_count=iterate_count)
    ble_obj = BleThread(wifi_dut=wifi_dut, test_case_no=test_case_no, ble_dut=ble_dut, ble_client=ble_client,
                        ble_clients=ble_clients, utf_constants=utf_constants)

    ble_obj.start()
    wlan_obj.start()
    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()
    wlan_obj.start()
    wlan_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_ble_3_connection_c18982(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client, index_path,
                                       http_server):
    test_case_no = 18982
    iterate_count = 5
    '''WiFi Sync Coex Static Test after 3 phones connection'''

    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat is True
    logger().info(f'http server state is {server_stat}')

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                          iterate_count=iterate_count, http_server=http_server)
    ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                        iterate_count=iterate_count)

    ble_obj.start()
    wlan_obj.start()
    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()