import pytest
from example_test_package.conftest import rs_helper_ble
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


"""Author : Vivek"""

"""This function runs below test steps for DUT-RS9116 for WLAN+BLE(Coex) Garmin test cases verification
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Verification of WiFi Sync Co-ex Static/Transient sync
        5. Multi connection(2/3/5) test required execution of WLAN and BLE operation simultaneously 
        6. WLAN thread execution scan/associate with third part AP, start the HTTP server and download files(with different sizes(1/10MB)
        7. BLE thread operates on single/multi-connection basis with different Master/Slave variations.
        8. BLE thread connection with DUT with or without SMP security.
        9. BLE connection verified with different parameter values like(connection interval, scan interval, advertisement interval)
        10. BLE connection verified with connection/disconnection multiple times.


    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4(6 raspberry device required to run the complete test cases)
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)
"""


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

        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"\n DUT MAC Address: {dut_mac_address}")
        self.device_address['dut_mac_address'] = dut_mac_address

        dut_ip = None
        for count in range(1, 4):
            try:
                ip_config = self.wifi_dut.interfaces.wifi.start_ip()
                assert isinstance(ip_config,
                                  self.wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
                dut_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                break
            except:
                logger().info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(10)
        assert dut_ip, "ip setting in DUT has failed"
        logger().info(f"\n DUT ip address: {dut_ip}")
        self.device_address['dut_ip_address'] = dut_ip

        return self.device_address

    def http_download(self, timeout=180):
        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
        logger().info(f"This API used to get the http data from the server ====={self.index_path}")
        status, content = self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path,
                                                                 timeout=timeout)
        status1, content1 = self.http_client.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)
        time.sleep(30)
        assert status, "failed to fetch the http data"
        assert content, "failed to load the http data"
        assert content == content1, f"http send and receive content is not same"

    def static_sync(self, timeout=450):
        ''' This function is responsible for series of test steps
        WLAN scan, connect, ipconfig, disconnect, HTTP download started
        :return:
        '''
        logger().info('\n\n ******* Start static sync process ****** \n\n')
        self.wlan_association()
        self.http_download(timeout=timeout)
        time.sleep(10)
        self.wifi_dut.interfaces.wifi.leave(timeout=20)
        time.sleep(2)
        self.wlan_association()


class DutBle:
    def __init__(self, wifi_dut=None, ble_dut=None, enable_smp=None):
        super().__init__()
        self.bt_dut_address = None
        self.ble_dut = ble_dut
        self.wifi_dut = wifi_dut
        self.enable_smp = enable_smp

    def start(self):
        self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.enable_smp)
        assert self.bt_dut_address is not None
        logger().info(f"\n\n Start DUT BLE \n DUT BLE Address is {self.bt_dut_address} with SMP {self.enable_smp}")

    def scan(self, bt_client_address=None, ble_scan_type=1, ble_scan_interval=256, ble_scan_window=80, timeout=10):
        logger().info("\n\n ***** start ble scan in DUT ***** \n\n")
        scan_report = self.ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address,
                                                                           ble_scan_type=ble_scan_type,
                                                                           ble_scan_interval=ble_scan_interval,
                                                                           ble_scan_window=ble_scan_window,
                                                                           timeout=timeout)

        if bt_client_address:
            logger().info(
                "\n\n\n\n\n\n *********Printing DUT Scan Report ********* \n\n\n\n\n\n {}".format(str(scan_report)))
            if "Found : {}".format(bt_client_address) in str(scan_report):
                logger().info("\n\n\n ***** Found {} in DUT's scan report ***** \n\n\n".format(bt_client_address))
            else:
                raise Exception("{} is not found in DUT's scan report".format(bt_client_address))

    def advertise(self, ble_adv_int_min=256, ble_adv_int_max=512, ble_adv_channel_map=7, timeout=10, ):
        logger().info("\n\n ***** start ble advertisement in DUT ***** \n\n")
        self.ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=ble_adv_int_min,
                                                                ble_adv_int_max=ble_adv_int_max, timeout=timeout,
                                                                ble_adv_channel_map=ble_adv_channel_map)

    def advertise_stop(self, timeout=10):
        logger().info("\n\n ***** stop ble advertisement in DUT ***** \n\n")
        self.ble_dut.interfaces.bluetooth.ble_stop_advertising(timeout=timeout)

    def connect(self, bt_client_address, ble_conn_interval_min=160, ble_conn_interval_max=160,
                ble_conn_latency=0,
                ble_supervision_timeout=2000, expected=None, timeout=30):

        if self.enable_smp == 1:
            expected = "RSI_BLE_ENCRYPT_STARTED_EVENT"
        elif self.enable_smp == 0:
            expected = 'success'
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

    def scan_stop(self, timeout=10):
        logger().info("\n\n ***** stop ble scan in DUT ***** \n\n")
        self.ble_dut.interfaces.bluetooth.ble_stop_scanning(timeout=timeout)

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

    def advertise(self, bt_dut_address=None, smp_adv=True):
        logger().info(f"\n\n ***** Start RESPI BLE with advertisement *****\n\n")
        if smp_adv:
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address)

    def scan(self, bt_client_address=None):
        logger().info("\n\n ***** Start smp scan from the RESPI device *****\n\n")
        bt_remote_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_client_address)
        assert bt_remote_address, "failed to initiate ble in remote device"
        return bt_remote_address

    def scan_stop(self):
        logger().info("\n\n ***** stop scanning in RESPI....*****\n\n")
        self.ble_client.interfaces.bluetooth.stop_scanning()

    def connect(self, bt_client_address, profile=None, ble_conn_interval_min=None, ble_conn_interval_max=None,
                ble_conn_latency=None, ble_supervision_timeout=None):
        logger().info(f"\n\n ***** RESPI ble is trying to connect to client = {bt_client_address} ***** \n")
        self.ble_client.interfaces.bluetooth.connect(bt_client_address, profile=profile,
                                                     min_conn_interval=ble_conn_interval_min,
                                                     max_conn_interval=ble_conn_interval_max,
                                                     conn_latency=ble_conn_latency,
                                                     supervision_timeout=ble_supervision_timeout)

    def advertise_stop(self):
        logger().info(f"\n\n ***** Stop RESPI BLE advertisement *****\n\n")
        self.ble_client.interfaces.bluetooth.stop_advertising()

    def disconnect(self, bt_device_address=None):
        logger().info(f"\n\n ***** Remote device is trying to disconnect to client = {bt_device_address} ***** \n")
        self.ble_client.interfaces.bluetooth.disconnect(bt_device_address)


class WlanThread(ThreadBase):
    iterate_count = 0
    flag = False

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
        # self.dut_obj = DutBle()
        self.count = 0
        self.iterate_count = iterate_count
        self.wlan_obj = Wlan(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                             wifi_sniffer=self.wifi_sniffer, http_server=self.http_server,
                             http_client=self.http_client, index_path=self.index_path)

    def run(self):
        if self.test_case_no == 18959:
            logger().info(f'\n\n ***** Start WLAN scan ***** \n')
            self.wifi_dut.interfaces.wifi.scan(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                               channel=self.wifi_access_point.interfaces.wifi.channel)
        if self.test_case_no == 18961:
            self.wlan_obj.static_sync(timeout=300)

        if self.test_case_no == 18963:
            for i in range(0, self.iterate_count):
                logger().info(f'\n\n ***** Start Wi-Fi sync iteration {i} ***** \n')
                self.wlan_obj.static_sync()
            WlanThread.flag = True
            logger().info(f'\n\n WLAN static_sync end')

        if self.test_case_no == 18964:
            self.wlan_obj.wlan_association()

        if self.test_case_no == 18972:
            for i in range(0, self.iterate_count):
                logger().info(f'\n\n ***** Start WLAN scan iteration {i} ***** \n')
                self.wifi_dut.interfaces.wifi.scan(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                   channel=self.wifi_access_point.interfaces.wifi.channel)
            WlanThread.flag = True
            logger().info(f'\n\n WLAN scan end')

        if self.test_case_no == 18983:
            self.wlan_obj.wlan_association()
            logger().info(f'\n\n ***** Start HTTP file download operation ***** \n')
            logger().info(f'\n\n ***** BleThread.counter_flag = {BleThread.counter_flag} ***** \n')
            while 1:
                self.wlan_obj.http_download()
                if BleThread.counter_flag is True:
                    break

            # sw = Stopwatch()
            # end_time = 500
            # start_time = sw.elapsed_sec
            # while start_time < end_time:
            #     if BleThread.counter_flag is True:
            #         break
            #     else:
            #         self.wlan_obj.http_download()

        if self.test_case_no == 18986:
            self.wlan_obj.static_sync(timeout=3000)

        if self.test_case_no == 18944:
            logger().info(f'\n\n ***** Start WLAN scan ***** \n')
            self.wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
            time.sleep(30)
            self.wlan_obj.wlan_association()

        if self.test_case_no == 18947:
            count = 0
            self.wlan_obj.wlan_association()
            sw = Stopwatch()
            end_time = 500
            while 1:
                if (BleThread.counter_flag is not True) or (sw.elapsed_sec < end_time):
                    break
                else:
                    self.wlan_obj.http_download()

        if self.test_case_no == 18951:
            while BleThread.execution_flag:
                BleThread.counter_flag = False
                self.wlan_obj.wlan_association()
                logger().info(f'\n\n ***** Start HTTP file download operation ***** \n')
                logger().info(f'\n\n ***** BleThread.counter_flag = {BleThread.counter_flag} ***** \n')
                while BleThread.counter_flag is not True:
                    self.wlan_obj.http_download()


class BleThread(ThreadBase):
    counter_flag = False
    execution_flag = True
    advertising = 1
    scanning = 2
    initiating = 4
    connected = 8
    standby = 0

    def __init__(self, wifi_dut=None, ble_dut=None, ble_client=None, test_case_no=None, iterate_count=None,
                 ble_sniffer=None, remote_devices_count=None, ble_clients=None, time_period=None, enable_smp=0,
                 utf_constants=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut = ble_dut
        self.enable_smp = enable_smp
        self.dut_ble = DutBle(self.wifi_dut, self.ble_dut, self.enable_smp)
        self.respi_ble = RespiBle(self.ble_client)
        self.test_case_no = test_case_no
        self.iterate_count = iterate_count
        self.verify = False
        self.ble_sniffer = ble_sniffer
        self.ble_clients = ble_clients
        self.time_period = time_period
        self.reconnect_count = 0

        if self.ble_clients:
            logger().info(f'\n\n ***** Total number of BLE clients in setup = {remote_devices_count}\n\n')
            if remote_devices_count == 2:
                self.ble_client1 = self.ble_clients[1]
                self.ble_client2 = self.ble_clients[2]
                respi1 = utf_constants.get("secondary_raspi_ble_client")
                respi2 = utf_constants.get("secondary_raspi_ble_client_1")
                assert ping(respi1, 10), '\n\n Please check RESPI 1 device in setup \n\n'
                assert ping(respi2, 10), '\n\n Please check RESPI 2 device in setup \n\n'
            if remote_devices_count == 3:
                self.ble_client1 = self.ble_clients[1]
                self.ble_client2 = self.ble_clients[2]
                self.ble_client3 = self.ble_clients[3]
                respi1 = utf_constants.get("secondary_raspi_ble_client")
                respi2 = utf_constants.get("secondary_raspi_ble_client_1")
                respi3 = utf_constants.get("secondary_raspi_ble_client_2")
                assert ping(respi1, 10), '\n\n Please check RESPI 1 device in setup \n\n'
                assert ping(respi2, 10), '\n\n Please check RESPI 2 device in setup \n\n'
                assert ping(respi3, 10), '\n\n Please check RESPI 3 device in setup \n\n'

            if remote_devices_count == 5:
                self.ble_client1 = self.ble_clients[1]
                self.ble_client2 = self.ble_clients[2]
                self.ble_client3 = self.ble_clients[3]
                self.ble_client4 = self.ble_clients[4]
                self.ble_client5 = self.ble_clients[5]
                respi1 = utf_constants.get("secondary_raspi_ble_client")
                respi2 = utf_constants.get("secondary_raspi_ble_client_1")
                respi3 = utf_constants.get("secondary_raspi_ble_client_2")
                respi4 = utf_constants.get("secondary_raspi_ble_client_3")
                respi5 = utf_constants.get("secondary_raspi_ble_client_4")
                assert ping(respi1, 10), '\n\n Please check RESPI 1 device in setup \n\n'
                assert ping(respi2, 10), '\n\n Please check RESPI 2 device in setup \n\n'
                assert ping(respi3, 10), '\n\n Please check RESPI 3 device in setup \n\n'
                assert ping(respi4, 10), '\n\n Please check RESPI 4 device in setup \n\n'
                assert ping(respi5, 10), '\n\n Please check RESPI 5 device in setup \n\n'

        if self.test_case_no == 18983:
            self.ble_conn_interval_min = 300
            self.ble_conn_interval_max = 300
            self.min_conn_interval = 45
            self.max_conn_interval = 45
            self.ble_supervision_timeout = 2000

        if self.test_case_no == 18939 or self.test_case_no == 18948 or self.test_case_no == 18949 \
                or self.test_case_no == 18951 or self.test_case_no == 18954 or self.test_case_no == 18956:
            self.ble_conn_interval_min = 240
            self.ble_conn_interval_max = 240
            self.min_conn_interval = 45
            self.max_conn_interval = 625
            self.ble_supervision_timeout = 400
            self.supervision_timeout = 800

    def transmit_notification(self, device_interface, service_uid, char_uid, data1, dut_side_notify=False):
        services, chars = device_interface.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()

        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        time.sleep(2)
        char_path, char_props = device_interface.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services,
            service_uid,
            char_uid)

        assert char_path is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        # read value - Notifications not enabled
        result = device_interface.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path)
        assert result == data1

        # subscribe to notifications
        device_interface.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path)
        time.sleep(2)
        device_interface.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                      char_uid=char_uid)
        time.sleep(2)

        # notify only
        if dut_side_notify:
            logger().info('\n\n **** BLE Notify started **** \n\n')
            self.ble_dut.interfaces.bluetooth.ble_notify_custom_value(data=data1)

    def multi_client_connection_with_services_notify(self):
        """Note need to change service id as per test case requirement """
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        conn_params = {"min_conn_interval": 45,
                       "max_conn_interval": 45}

        conn_params1 = {"min_conn_interval": 500,
                        "max_conn_interval": 500}
        data1 = "LzY0"

        logger().info("start ble in dut")
        self.dut_ble.start()

        '''Right these function are getting fail will uncomment when fix available'''
        self.dut_ble.add_service(uid_name=0x6E)
        self.dut_ble.add_characteristic(uid_name=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
        self.dut_ble.scan(ble_scan_type=1, timeout=20)
        time.sleep(5)
        self.dut_ble.advertise()
        time.sleep(1)
        self.ble_client1.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(1)

        logger().info(f"\n\n DUT connected to first RESPI \n\n")
        # Connect BLE client 1 to DUT
        self.ble_client1.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                      min_conn_interval=conn_params["min_conn_interval"],
                                                      max_conn_interval=conn_params["max_conn_interval"])

        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\n\n device state is = {state_int}")
        assert state_int >= BLEDeviceState.Connected

        time.sleep(5)
        self.dut_ble.advertise()

        time.sleep(1)
        self.ble_client2.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)

        time.sleep(2)
        # Connect BLE client 2 to DUT
        logger().info(f"\n\n DUT connected to second RESPI \n\n")
        self.ble_client2.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                      min_conn_interval=conn_params1["min_conn_interval"],
                                                      max_conn_interval=conn_params1["max_conn_interval"])

        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\n\n device state is = {state_int}")
        assert state_int >= BLEDeviceState.Connected

        time.sleep(1)
        logger().info(f'\n\n Remote device 1 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client1, service_uid, char_uid, data1)

        time.sleep(5)
        logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client2, service_uid, char_uid, data1)

    def multi_client_connection_disconnection_with_services_notify(self):
        """Note need to change service id as per test case requirement """
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        conn_params = {"min_conn_interval": 45,
                       "max_conn_interval": 45}

        conn_params1 = {"min_conn_interval": 500,
                        "max_conn_interval": 500}

        data1 = "LzY0"
        logger().info("start ble in dut")
        self.dut_ble.start()

        '''Right now these function are getting fail will uncomment when fix available'''
        self.dut_ble.add_service(uid_name=0x6E)
        self.dut_ble.add_characteristic(uid_name=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

        '''Missing scan window value in Test plan need information'''
        self.dut_ble.scan(ble_scan_type=1, timeout=20)
        time.sleep(1)
        logger().info("\n\n ***** Start Adv in DUT(Slave) 1st time***** \n\n\n")
        self.dut_ble.advertise()
        time.sleep(5)
        logger().info("\n\n ***** Start scan in RESPI 1 ***** \n\n\n")
        self.ble_client1.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(2)
        self.ble_client1.interfaces.bluetooth.stop_scanning()

        # Connect BLE client 1 to DUT
        logger().info("Initiating BLE connection")
        logger().info("\n\n ***** Initiating BLE connection from RESPI 1 ***** \n\n\n")
        time.sleep(2)
        self.ble_client1.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                      min_conn_interval=conn_params["min_conn_interval"],
                                                      max_conn_interval=conn_params["max_conn_interval"])

        time.sleep(10)
        logger().info("\n\n ***** Start Adv in DUT(Slave) 2nd time***** \n\n\n")
        self.dut_ble.advertise()
        time.sleep(5)
        logger().info("\n\n ***** Start scan in RESPI 2 ***** \n\n\n")
        self.ble_client2.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(2)
        self.ble_client2.interfaces.bluetooth.stop_scanning()

        # Connect BLE client 2 to DUT
        logger().info("Initiating BLE connection")
        logger().info("\n\n ***** Initiating BLE connection from RESPI 2 ***** \n\n\n")
        time.sleep(2)
        self.ble_client2.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                      min_conn_interval=conn_params1["min_conn_interval"],
                                                      max_conn_interval=conn_params1["max_conn_interval"])

        assert self.ble_client1.interfaces.bluetooth.get_connection_status(self.dut_ble.bt_dut_address)
        time.sleep(15)
        assert self.ble_client2.interfaces.bluetooth.get_connection_status(self.dut_ble.bt_dut_address)
        time.sleep(15)

        time.sleep(1)
        logger().info(f'\n\n Remote device 1 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client1, service_uid, char_uid, data1)

        time.sleep(5)
        logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client2, service_uid, char_uid, data1)

    def multi_client_connection_with_different_connection_intervals(self):
        """Note need to change service id as per test case requirement """
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        conn_params = {"min_conn_interval": 45,
                       "max_conn_interval": 45}

        conn_params1 = {"min_conn_interval": 500,
                        "max_conn_interval": 500}

        data1 = "LzY0"
        logger().info("start ble in dut")
        self.dut_ble.start()

        '''Right now these function are getting fail will uncomment when fix available'''
        self.dut_ble.add_service(uid_name=0x6E)
        self.dut_ble.add_characteristic(uid_name=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

        '''Missing scan window value in Test plan need information'''
        self.dut_ble.scan(ble_scan_type=1, timeout=20)
        time.sleep(10)
        self.dut_ble.scan_stop()

        logger().info("\n\n ***** Start Adv in DUT(Slave) 1st time***** \n\n\n")
        self.dut_ble.advertise()
        time.sleep(1)
        self.ble_client1.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(2)
        self.ble_client1.interfaces.bluetooth.stop_scanning()

        # Connect BLE client 1 to DUT
        logger().info("Initiating BLE connection")
        logger().info("\n\n ***** Initiating BLE connection from RESPI 1 ***** \n\n\n")
        time.sleep(2)
        self.ble_client1.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                      min_conn_interval=conn_params["min_conn_interval"],
                                                      max_conn_interval=conn_params["max_conn_interval"])

        logger().info("BLE Connection success")
        time.sleep(2)
        logger().info("\n\n ***** Start Adv in DUT(Slave) 2nd time ***** \n\n\n")
        self.dut_ble.advertise()
        time.sleep(2)
        logger().info("\n\n ***** Start scan in RESPI 2 ***** \n\n\n")
        self.ble_client2.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(2)
        self.ble_client2.interfaces.bluetooth.stop_scanning()

        # Connect BLE client 2 to DUT
        logger().info("Initiating BLE connection")
        logger().info("\n\n ***** Initiating BLE connection from RESPI 2 ***** \n\n\n")
        self.ble_client2.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                      min_conn_interval=conn_params1["min_conn_interval"],
                                                      max_conn_interval=conn_params1["max_conn_interval"])

        assert self.ble_client1.interfaces.bluetooth.get_connection_status(self.dut_ble.bt_dut_address)
        time.sleep(15)
        assert self.ble_client2.interfaces.bluetooth.get_connection_status(self.dut_ble.bt_dut_address)
        time.sleep(15)

        logger().info(f'\n\n Remote device 1 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client1, service_uid, char_uid, data1)

        time.sleep(5)
        logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client2, service_uid, char_uid, data1)

        '''Change connection parameters High(11.25-15ms), Balanced(30-50ms), Low power(100-125ms) and check whether 
            this modification causing any BLE disconnection'''

        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log.log_{int(time.time())}"):
            time.sleep(5)
            # Update connection Interval for first remote device
            logger().info("\n\n Updating ble connection with connection parameters for 1st RESPI \n\n")
            self.ble_client1.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                dev_addr=self.dut_ble.bt_dut_address,
                connection_interval_min="0x0C 0x00",
                connection_interval_max="0x0C 0x00",
                supervision_timeout="0xF4 0x01",
            )

            time.sleep(5)
            logger().info("Updating ble connection with connection parameters")
            self.ble_client1.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                dev_addr=self.dut_ble.bt_dut_address,
                connection_interval_min="0x20 0x00",
                connection_interval_max="0x20 0x00",
                supervision_timeout="0xF4 0x01",
            )

            time.sleep(5)
            logger().info("Updating ble connection with connection parameters")
            self.ble_client1.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                dev_addr=self.dut_ble.bt_dut_address,
                connection_interval_min="0x5A 0x00",
                connection_interval_max="0x5A 0x00",
                supervision_timeout="0xF4 0x01",
            )

            time.sleep(10)
            logger().info("\n\n Updating ble connection with connection parameters for 2nd RESPI \n\n")
            self.ble_client2.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                dev_addr=self.dut_ble.bt_dut_address,
                connection_interval_min="0x0C 0x00",
                connection_interval_max="0x0C 0x00",
                supervision_timeout="0xF4 0x01",
            )

            time.sleep(5)
            logger().info("Updating ble connection with connection parameters")
            self.ble_client2.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                dev_addr=self.dut_ble.bt_dut_address,
                connection_interval_min="0x20 0x00",
                connection_interval_max="0x20 0x00",
                supervision_timeout="0xF4 0x01",
            )

            time.sleep(5)
            logger().info("Updating ble connection with connection parameters")
            self.ble_client2.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                dev_addr=self.dut_ble.bt_dut_address,
                connection_interval_min="0x5A 0x00",
                connection_interval_max="0x5A 0x00",
                supervision_timeout="0xF4 0x01",
            )

    def multi_client_connection_3_with_services_notify(self):
        """Note need to change service id as per test case requirement """
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

        data1 = "LzY0LzY0LzY0LzY0LzY0"

        logger().info("start ble in dut")
        self.dut_ble.start()

        '''Right these function are getting fail will uncomment when fix available'''
        self.dut_ble.add_service(uid_name=0x6E)
        self.dut_ble.add_characteristic(uid_name=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
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
        logger().info("\n\n **** Initiating BLE connection with ble_client 1 **** \n\n")
        self.dut_ble.connect(bt_client_address=ble1_client_address, ble_conn_interval_min=300,
                             ble_conn_interval_max=300)
        logger().info("BLE Connection success")
        time.sleep(10)

        # Start connection between DUT & RESPI 2 client
        ble2_client_address = self.ble_client2.interfaces.bluetooth.start_smp_adv(self.dut_ble.bt_dut_address)
        assert ble2_client_address, "Unable to get ble_client_address"
        time.sleep(5)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble2_client_address, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("\n\n **** Initiating BLE connection with ble_client 2 ****\n\n")
        self.dut_ble.connect(bt_client_address=ble2_client_address, ble_conn_interval_min=300,
                             ble_conn_interval_max=300)
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
        logger().info("\n\n **** Initiating BLE connection with ble_client 3 ****\n\n")
        self.dut_ble.connect(bt_client_address=ble3_client_address, ble_conn_interval_min=300,
                             ble_conn_interval_max=300)
        # self.dut_ble.connect(ble2_client_address)
        logger().info("BLE Connection success")
        time.sleep(10)

        logger().info(f'\n\n Remote device 1 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client1, service_uid, char_uid, data1, dut_side_notify=True)

        logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client2, service_uid, char_uid, data1, dut_side_notify=True)

    def multi_client_connection_5_with_services_notify(self, no_of_notify_connection=None,
                                                       smp_enable_client=False, reconnection=False):
        """Note need to change service id as per test case requirement """

        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        data1 = "LzY0ZLzY0ZLzY0ZLzY0Z"
        if self.reconnect_count == 0:
            logger().info("start ble in dut")
            self.dut_ble.start()

            '''Right these function are getting fail will uncomment when fix available'''
            self.dut_ble.add_service(uid_name=0x6E)
            self.dut_ble.add_characteristic(uid_name=0x6F)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
            time.sleep(5)

        # Start connection between DUT & RESPI 1 client
        logger().info("\n\n ***** Start Adv in RESPI 1 ***** \n\n\n")
        ble1_client_address = self.ble_client1.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=self.dut_ble.bt_dut_address,
            hci_adv_params="0x152 0x00 "  # Advertising_Interval_Min
                           "0x152 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x00 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
        )
        assert ble1_client_address, "Unable to get ble_client_address"
        time.sleep(5)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble1_client_address, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 1 ***** \n\n\n")
        self.dut_ble.connect(bt_client_address=ble1_client_address, ble_conn_interval_min=self.ble_conn_interval_min,
                             ble_conn_interval_max=self.ble_conn_interval_max,
                             ble_supervision_timeout=self.ble_supervision_timeout)

        logger().info("BLE Connection success")
        time.sleep(10)

        # Start connection between DUT & RESPI 2 client
        logger().info("\n\n ***** Start Adv in RESPI 2 ***** \n\n\n")
        ble2_client_address = self.ble_client2.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=self.dut_ble.bt_dut_address,
            hci_adv_params="0x152 0x00 "  # Advertising_Interval_Min
                           "0x152 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x00 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
        )
        assert ble2_client_address, "Unable to get ble_client_address"
        time.sleep(5)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble2_client_address, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 2 ***** \n\n\n")
        self.dut_ble.connect(bt_client_address=ble2_client_address, ble_conn_interval_min=self.ble_conn_interval_min,
                             ble_conn_interval_max=self.ble_conn_interval_max,
                             ble_supervision_timeout=self.ble_supervision_timeout)

        logger().info("BLE Connection success")
        time.sleep(10)

        # Start connection between DUT & RESPI 3 client
        logger().info("\n\n ***** Start Adv in RESPI 3 ***** \n\n\n")
        ble3_client_address = self.ble_client3.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=self.dut_ble.bt_dut_address,
            hci_adv_params="0x152 0x00 "  # Advertising_Interval_Min
                           "0x152 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x00 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
        )
        assert ble3_client_address, "Unable to get ble_client_address"
        time.sleep(10)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble3_client_address, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 3 ***** \n\n\n")
        self.dut_ble.connect(bt_client_address=ble3_client_address, ble_conn_interval_min=self.ble_conn_interval_min,
                             ble_conn_interval_max=self.ble_conn_interval_max,
                             ble_supervision_timeout=self.ble_supervision_timeout)

        logger().info("BLE Connection success")
        time.sleep(20)

        ''' Second condition where DUT will be Server(advertiser) and 2 other RESPI act as a client(Scan + Connect) '''
        logger().info("\n\n ***** Start Adv in DUT(Slave) 1st time***** \n\n\n")
        self.dut_ble.advertise()
        time.sleep(5)

        logger().info("\n\n ***** Start scan in RESPI 4 ***** \n\n\n")
        self.ble_client4.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(2)
        self.ble_client4.interfaces.bluetooth.stop_scanning()

        logger().info("Initiating BLE connection")
        logger().info("\n\n ***** Initiating BLE connection from RESPI 4 ***** \n\n\n")
        time.sleep(2)

        if smp_enable_client:
            ''' Trying to connect DUT with SMP enable client device '''
            logger().info(f'\n\n *****Trying to connect DUT with SMP enable client 4 device *****\n\n\n')
            self.ble_client4.interfaces.bluetooth.pair_and_connect(dev_addr=self.dut_ble.bt_dut_address)
        else:
            self.ble_client4.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                          min_conn_interval=self.min_conn_interval,
                                                          max_conn_interval=self.min_conn_interval)

        logger().info("BLE Connection success")
        time.sleep(2)
        logger().info("\n\n ***** Start Adv in DUT(Slave) 2nd time ***** \n\n\n")

        time.sleep(2)
        self.dut_ble.advertise()
        time.sleep(2)
        logger().info("\n\n ***** Start scan in RESPI 5 ***** \n\n\n")
        self.ble_client5.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(2)
        self.ble_client5.interfaces.bluetooth.stop_scanning()

        time.sleep(4)
        logger().info("Initiating BLE connection")
        logger().info("\n\n ***** Initiating BLE connection from RESPI 5 ***** \n\n\n")
        time.sleep(2)

        if smp_enable_client:
            ''' Trying to connect DUT with SMP enable client device '''
            logger().info(f'\n\n *****Trying to connect DUT with SMP enable client 5 device *****\n\n\n')
            self.ble_client5.interfaces.bluetooth.pair_and_connect(dev_addr=self.dut_ble.bt_dut_address)
        else:
            self.ble_client5.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                          min_conn_interval=self.min_conn_interval,
                                                          max_conn_interval=self.min_conn_interval)

        logger().info("\n\n ***** Check BLE connection status for DUT as a Master(3 connection) "
                      "Whether its connected or not ***** \n\n\n")
        assert self.ble_client1.interfaces.bluetooth.get_connection_status(self.dut_ble.bt_dut_address)
        time.sleep(15)
        assert self.ble_client2.interfaces.bluetooth.get_connection_status(self.dut_ble.bt_dut_address)
        time.sleep(15)
        assert self.ble_client3.interfaces.bluetooth.get_connection_status(self.dut_ble.bt_dut_address)
        time.sleep(15)

        logger().info("BLE Connection success")

        if no_of_notify_connection == 2:
            logger().info(f'\n\n Remote device 4 will discover services and characteristic of DUT \n\n')
            self.transmit_notification(self.ble_client4, service_uid, char_uid, data1)

            logger().info(f'\n\n Remote device 5 will discover services and characteristic of DUT \n\n')
            self.transmit_notification(self.ble_client5, service_uid, char_uid, data1)

        if no_of_notify_connection == 3:
            logger().info(f'\n\n Remote device 1 will discover services and characteristic of DUT \n\n')
            self.transmit_notification(self.ble_client1, service_uid, char_uid, data1)

            logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
            self.transmit_notification(self.ble_client2, service_uid, char_uid, data1)

            logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
            self.transmit_notification(self.ble_client3, service_uid, char_uid, data1)

        if no_of_notify_connection == 5:
            logger().info(f'\n\n Remote device 1 will discover services and characteristic of DUT \n\n')
            self.transmit_notification(self.ble_client1, service_uid, char_uid, data1)

            logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
            self.transmit_notification(self.ble_client2, service_uid, char_uid, data1)

            logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
            self.transmit_notification(self.ble_client3, service_uid, char_uid, data1)

            logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
            self.transmit_notification(self.ble_client4, service_uid, char_uid, data1)

            logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
            self.transmit_notification(self.ble_client5, service_uid, char_uid, data1)

        logger().info(f'\n\n ***** CLEAR ALL CLIENTS STATE ***** \n\n\n')
        self.dut_ble.disconnect(ble_remote_dev_address=ble1_client_address)
        self.dut_ble.disconnect(ble_remote_dev_address=ble2_client_address)
        self.dut_ble.disconnect(ble_remote_dev_address=ble3_client_address)

        logger().info(f'\n\n ***** Unregistering  Clients 1/2/3***** \n\n\n')
        self.ble_client1.interfaces.bluetooth.close()
        self.ble_client2.interfaces.bluetooth.close()
        self.ble_client3.interfaces.bluetooth.close()

        logger().info(f'\n\n ***** Disconnect & Unregistering  Clients 4&5 ***** \n\n\n')
        self.ble_client4.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)
        self.ble_client5.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)
        self.ble_client4.interfaces.bluetooth.close()
        self.ble_client5.interfaces.bluetooth.close()

        dut_state = int(self.ble_dut.interfaces.wifi.ble_get_device_state())
        logger().info(f'\n\n **** DUT CURRENT STATE is {dut_state}***** \n\n\n')

        if reconnection:
            while self.reconnect_count < 3:
                logger().info(f'\n\n **** RECONNECTION START = {self.reconnect_count}***** \n\n\n')
                self.reconnect_count += 1
                self.multi_client_connection_5_with_services_notify(reconnection=reconnection,
                                                                    smp_enable_client=smp_enable_client,
                                                                    no_of_notify_connection=no_of_notify_connection)

    def multi_client_connection_5_with_different_adv_intervals(self, ble_adv_interval):
        """Note need to change service id as per test case requirement """
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        data1 = "LzY0ZLzY0ZLzY0ZLzY0Z"
        if ble_adv_interval == '0x152 0x00 ':
            dut_ble_adv_interval = 211
        if ble_adv_interval == '0x06a8 0x00 ':
            dut_ble_adv_interval = 4197
        if ble_adv_interval == '0x20 0x00 ':
            dut_ble_adv_interval = 32
        if ble_adv_interval == '0xa0 0x00 ':
            dut_ble_adv_interval = 256
        if ble_adv_interval == '0x4000 0x00 ':
            dut_ble_adv_interval = 4132

        logger().info("start ble in dut")
        self.dut_ble.start()

        '''Right these function are getting fail will uncomment when fix available'''
        self.dut_ble.add_service(uid_name=0x6E)
        self.dut_ble.add_characteristic(uid_name=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
        time.sleep(5)

        # Start connection between DUT & RESPI 1 client
        ble1_client_address = self.ble_client1.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=self.dut_ble.bt_dut_address,
            hci_adv_params="ble_adv_interval"  # Advertising_Interval_Min
                           "ble_adv_interval"  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x00 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
        )
        assert ble1_client_address, "Unable to get ble_client_address"
        logger().info("Start scanning and connect to ble client")
        time.sleep(5)
        self.dut_ble.scan(bt_client_address=ble1_client_address, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(2)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 1 ***** \n\n\n")
        self.dut_ble.connect(bt_client_address=ble1_client_address, ble_conn_interval_min=self.ble_conn_interval_min,
                             ble_conn_interval_max=self.ble_conn_interval_max)
        # self.dut_ble.connect(ble1_client_address)
        logger().info("BLE Connection success")
        time.sleep(15)

        # Start connection between DUT & RESPI 2 client
        ble2_client_address = self.ble_client2.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=self.dut_ble.bt_dut_address,
            hci_adv_params="ble_adv_interval"  # Advertising_Interval_Min
                           "ble_adv_interval"  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x00 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
        )
        assert ble2_client_address, "Unable to get ble_client_address"
        time.sleep(5)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble2_client_address, timeout=80)
        time.sleep(2)
        self.dut_ble.scan_stop()
        time.sleep(2)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 2 ***** \n\n\n")
        self.dut_ble.connect(bt_client_address=ble2_client_address, ble_conn_interval_min=self.ble_conn_interval_min,
                             ble_conn_interval_max=self.ble_conn_interval_max)
        # self.dut_ble.connect(ble2_client_address)
        logger().info("BLE Connection success")
        time.sleep(15)

        # Start connection between DUT & RESPI 3 client
        ble3_client_address = self.ble_client3.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=self.dut_ble.bt_dut_address,
            hci_adv_params="ble_adv_interval"  # Advertising_Interval_Min
                           "ble_adv_interval"  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x00 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
        )
        assert ble3_client_address, "Unable to get ble_client_address"
        time.sleep(15)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble3_client_address, timeout=120)
        time.sleep(2)
        self.dut_ble.scan_stop()
        time.sleep(2)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 3 ***** \n\n\n")
        self.dut_ble.connect(bt_client_address=ble3_client_address, ble_conn_interval_min=self.ble_conn_interval_min,
                             ble_conn_interval_max=self.ble_conn_interval_max)
        # self.dut_ble.connect(ble2_client_address)
        logger().info("BLE Connection success")
        time.sleep(25)

        ''' Second condition where DUT will be Slave(advertiser) and 2 other RESPI act as a Master(Scan + Connect) '''

        # Initiate connection for 4th connection
        ''' Second condition where DUT will be Server(advertiser) and 2 other RESPI act as a client(Scan + Connect) '''
        logger().info("\n\n ***** Start Adv in DUT as a Slave ***** \n\n\n")
        self.dut_ble.advertise(ble_adv_int_min=dut_ble_adv_interval, ble_adv_int_max=dut_ble_adv_interval)
        time.sleep(5)
        self.ble_client4.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(10)
        logger().info("\n\n ***** Initiating BLE connection for 4th device *****\n\n ")
        self.ble_client4.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                      min_conn_interval=self.min_conn_interval,
                                                      max_conn_interval=self.max_conn_interval,
                                                      supervision_timeout=self.supervision_timeout)
        time.sleep(10)
        # Initiate connection for 5th connection
        self.dut_ble.advertise(ble_adv_int_min=dut_ble_adv_interval, ble_adv_int_max=dut_ble_adv_interval)
        time.sleep(5)
        self.ble_client5.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(10)
        logger().info("\n\n ***** Initiating BLE connection for 5th device *****\n\n ")
        self.ble_client5.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                      min_conn_interval=self.min_conn_interval,
                                                      max_conn_interval=self.min_conn_interval,
                                                      supervision_timeout=self.supervision_timeout)
        logger().info("BLE Connection success")

        time.sleep(10)
        logger().info(f'\n\n Remote device will discover services and characteristic of DUT \n\n')

        logger().info(f'\n\n Remote device 1 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client4, service_uid, char_uid, data1)

        logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client5, service_uid, char_uid, data1)

        time.sleep(2)
        logger().info(f'\n\n ***** CLEAR ALL CLIENTS STATE ***** \n\n\n')
        self.dut_ble.disconnect(ble_remote_dev_address=ble1_client_address)
        self.dut_ble.disconnect(ble_remote_dev_address=ble2_client_address)
        self.dut_ble.disconnect(ble_remote_dev_address=ble3_client_address)

        logger().info(f'\n\n ***** Unregistering  Clients 1/2/3***** \n\n\n')
        self.ble_client1.interfaces.bluetooth.close()
        self.ble_client2.interfaces.bluetooth.close()
        self.ble_client3.interfaces.bluetooth.close()

        logger().info(f'\n\n ***** Disconnect & Unregistering  Clients 4/5 ***** \n\n\n')
        self.ble_client4.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)
        self.ble_client5.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)
        self.ble_client4.interfaces.bluetooth.close()
        self.ble_client5.interfaces.bluetooth.close()
        dut_state = int(self.ble_dut.interfaces.wifi.ble_get_device_state())
        logger().info(f'\n\n\n ***** DEVICE STATE = {dut_state} *****\n\n\n ')

    def multi_client_connection_5_with_different_scan_intervals(self, ble_scan_interval, ble_scan_window):
        """Note need to change service id as per test case requirement """
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        data1 = "LzY0LzY0LzY0LzY0LzY0"

        logger().info("start ble in dut")
        self.dut_ble.start()

        '''Right these function are getting fail will uncomment when fix available'''
        self.dut_ble.add_service(uid_name=0x6E)
        self.dut_ble.add_characteristic(uid_name=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
        time.sleep(5)

        # Start connection between DUT & RESPI 1 client
        ble1_client_address = self.ble_client1.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=self.dut_ble.bt_dut_address)
        assert ble1_client_address, "Unable to get ble_client_address"
        time.sleep(1)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble1_client_address, ble_scan_interval=ble_scan_interval,
                          ble_scan_window=ble_scan_window, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 1 ***** \n\n\n")
        self.dut_ble.connect(bt_client_address=ble1_client_address)
        logger().info("BLE Connection success with RESP 1")
        time.sleep(1)

        # Start connection between DUT & RESPI 2 client
        ble2_client_address = self.ble_client2.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=self.dut_ble.bt_dut_address)
        assert ble2_client_address, "Unable to get ble_client_address"
        time.sleep(1)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble2_client_address, ble_scan_interval=ble_scan_interval,
                          ble_scan_window=ble_scan_window, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 2 ***** \n\n\n")
        self.dut_ble.connect(bt_client_address=ble2_client_address)
        logger().info("BLE Connection success with RESPI 2")
        time.sleep(1)

        # Start connection between DUT & RESPI 3 client
        ble3_client_address = self.ble_client3.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=self.dut_ble.bt_dut_address)
        assert ble3_client_address, "Unable to get ble_client_address"
        time.sleep(1)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble3_client_address, ble_scan_interval=ble_scan_interval,
                          ble_scan_window=ble_scan_window, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 3 ***** \n\n\n")
        self.dut_ble.connect(bt_client_address=ble3_client_address)
        logger().info("BLE Connection success with RESP 3")
        time.sleep(15)

        ''' Second condition where DUT will be Server(advertiser) and 2 other RESPI act as a client(Scan + Connect) '''

        # Initiate connection for 4th connection
        self.dut_ble.advertise()
        self.ble_client4.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(2)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 4 ***** \n\n\n")
        self.ble_client4.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address)
        logger().info("BLE Connection success")
        time.sleep(10)

        # Initiate connection for 5th connection
        self.dut_ble.advertise()
        self.ble_client5.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(2)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 5 ***** \n\n\n")
        self.ble_client5.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address)
        logger().info("BLE Connection success")

        logger().info(f'\n\n Remote device 1 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client4, service_uid, char_uid, data1)

        logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client5, service_uid, char_uid, data1)

        time.sleep(2)
        logger().info(f'\n\n ***** CLEAR ALL CLIENTS STATE ***** \n\n\n')
        self.dut_ble.disconnect(ble_remote_dev_address=ble1_client_address)
        self.dut_ble.disconnect(ble_remote_dev_address=ble2_client_address)
        self.dut_ble.disconnect(ble_remote_dev_address=ble3_client_address)

        logger().info(f'\n\n ***** Unregistering  Clients 1/2/3***** \n\n\n')
        self.ble_client1.interfaces.bluetooth.close()
        self.ble_client2.interfaces.bluetooth.close()
        self.ble_client3.interfaces.bluetooth.close()

        logger().info(f'\n\n ***** Disconnect & Unregistering  Clients 4/5 ***** \n\n\n')
        self.ble_client4.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)
        self.ble_client5.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)
        self.ble_client4.interfaces.bluetooth.close()
        self.ble_client5.interfaces.bluetooth.close()
        dut_state = int(self.ble_dut.interfaces.wifi.ble_get_device_state())
        logger().info(f'\n\n\n ***** DEVICE STATE = {dut_state} *****\n\n\n ')

    def multi_client_connection_5_with_different_connection_intervals(self, ble_connection_interval):
        """Note need to change service id as per test case requirement """
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        data1 = "LzY0LzY0LzY0LzY0LzY0"

        logger().info("start ble in dut")
        self.dut_ble.start()

        '''Right these function are getting fail will uncomment when fix available'''
        self.dut_ble.add_service(uid_name=0x6E)
        self.dut_ble.add_characteristic(uid_name=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

        # Start connection between DUT & RESPI 1 client
        ble1_client_address = self.ble_client1.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=self.dut_ble.bt_dut_address)
        assert ble1_client_address, "Unable to get ble_client_address"
        time.sleep(1)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble1_client_address, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("Initiating BLE connection with ble_client")
        self.dut_ble.connect(bt_client_address=ble1_client_address, ble_conn_interval_min=ble_connection_interval,
                             ble_conn_interval_max=ble_connection_interval)
        logger().info("BLE Connection success")
        time.sleep(1)

        # Start connection between DUT & RESPI 2 client
        ble2_client_address = self.ble_client2.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=self.dut_ble.bt_dut_address)
        assert ble2_client_address, "Unable to get ble_client_address"
        time.sleep(1)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble2_client_address, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("Initiating BLE connection with ble_client")
        self.dut_ble.connect(bt_client_address=ble2_client_address, ble_conn_interval_min=ble_connection_interval,
                             ble_conn_interval_max=ble_connection_interval)
        # self.dut_ble.connect(ble2_client_address)
        logger().info("BLE Connection success")
        time.sleep(1)

        # Start connection between DUT & RESPI 3 client
        ble3_client_address = self.ble_client3.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=self.dut_ble.bt_dut_address)
        assert ble3_client_address, "Unable to get ble_client_address"
        time.sleep(1)
        logger().info("Start scanning and connect to ble client")
        self.dut_ble.scan(bt_client_address=ble3_client_address, timeout=80)
        self.dut_ble.scan_stop()
        time.sleep(1)
        logger().info("Initiating BLE connection with ble_client")
        self.dut_ble.connect(bt_client_address=ble3_client_address, ble_conn_interval_min=ble_connection_interval,
                             ble_conn_interval_max=ble_connection_interval)
        # self.dut_ble.connect(ble2_client_address)
        logger().info("BLE Connection success")
        time.sleep(1)

        ''' Second condition where DUT will be Server(advertiser) and 2 other RESPI act as a client(Scan + Connect) '''

        # Initiate connection for 4th connection
        self.dut_ble.advertise()
        self.ble_client4.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(2)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 4 ***** \n\n\n")
        self.ble_client4.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address)
        logger().info("BLE Connection success")

        # Initiate connection for 5th connection
        self.dut_ble.advertise()
        self.ble_client5.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)
        time.sleep(2)
        logger().info("\n\n ***** Initiating BLE connection with RESPI 5 ***** \n\n\n")
        self.ble_client5.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address)
        logger().info("BLE Connection success")

        logger().info(f'\n\n Remote device 1 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client1, service_uid, char_uid, data1)

        logger().info(f'\n\n Remote device 2 will discover services and characteristic of DUT \n\n')
        self.transmit_notification(self.ble_client2, service_uid, char_uid, data1)

        time.sleep(2)
        logger().info(f'\n\n ***** CLEAR ALL CLIENTS STATE ***** \n\n\n')
        self.dut_ble.disconnect(ble_remote_dev_address=ble1_client_address)
        self.dut_ble.disconnect(ble_remote_dev_address=ble2_client_address)
        self.dut_ble.disconnect(ble_remote_dev_address=ble3_client_address)

        logger().info(f'\n\n ***** Unregistering  Clients 1/2/3***** \n\n\n')
        self.ble_client1.interfaces.bluetooth.close()
        self.ble_client2.interfaces.bluetooth.close()
        self.ble_client3.interfaces.bluetooth.close()

        logger().info(f'\n\n ***** Disconnect & Unregistering  Clients 4/5 ***** \n\n\n')
        self.ble_client4.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)
        self.ble_client5.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)
        self.ble_client4.interfaces.bluetooth.close()
        self.ble_client5.interfaces.bluetooth.close()
        dut_state = int(self.ble_dut.interfaces.wifi.ble_get_device_state())
        logger().info(f'\n\n\n ***** DEVICE STATE = {dut_state} *****\n\n\n ')

    def multi_2masters_1slave_ble_conn_disconn_recon(self):
        no_of_reconnects = 1
        for i in range(no_of_reconnects+1):
            self.dut_ble.start()
            self.ble_client1.interfaces.bluetooth.close()

            logger().info(f"\n\n*****************start advertising on ble client1 ******************\n\n")
            ble1_client_address = self.ble_client1.interfaces.bluetooth.start_smp_adv(self.dut_ble.bt_dut_address)
            assert ble1_client_address, "Unable to get ble_client_address"
            logger().info(f" ble client_1 address : {ble1_client_address}")
            time.sleep(5)

            logger().info(f"\n\n***Start scanning and connect to ble client****\n\n")
            self.dut_ble.scan(bt_client_address=ble1_client_address, timeout=120)
            self.dut_ble.scan_stop()

            logger().info(f"\n\n*****Initiating dut BLE connection with ble_client1*****\n\n")
            self.dut_ble.connect(bt_client_address=ble1_client_address, timeout=120)
            time.sleep(30)
            logger().info(f"\n\n************ble master connection success**************\n\n")


            self.ble_client2.interfaces.bluetooth.close()
            logger().info(f"\n\n*****************start advertising on ble client2 ******************\n\n")
            ble2_client_address = self.ble_client2.interfaces.bluetooth.start_smp_adv(self.dut_ble.bt_dut_address)
            assert ble2_client_address, "Unable to get ble_client_address"
            logger().info(f" ble client_3 address : {ble2_client_address}")
            time.sleep(5)
            logger().info(f"\n\n***********Start scanning and connect to ble client*********\n\n")
            self.dut_ble.scan(bt_client_address=ble2_client_address, timeout=120)
            self.dut_ble.scan_stop()
            time.sleep(5)

            logger().info(f"\n\n*********Initiating Dut BLE connection with ble_client2*************\n\n")
            self.dut_ble.connect(bt_client_address=ble2_client_address, timeout=120)
            time.sleep(30)
            logger().info(f"\n\n************ble master connection success**************\n\n")


            logger().info(f"\n\n************start advertising on dut*******************\n\n")
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            self.ble_client3.interfaces.bluetooth.close()
            logger().info(f"\n\n************start Scanning from ble client3 ***************\n\n")
            ble3_client_address = self.ble_client3.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=self.dut_ble.bt_dut_address)
            assert ble3_client_address, f"failed to initiate ble in remote device"
            time.sleep(5)
            self.ble_client3.interfaces.bluetooth.stop_scanning()

            found_devices = self.ble_client3.interfaces.bluetooth.get_devices()
            logger().info(f"ble_scan_list:\n{found_devices}")
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices, "Unable to find out DUT"
            assert (found_devices[
                        self.wifi_dut.interfaces.wifi.ble_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data), "Could not able to find our DUT"
            logger().info(f"\n\n*****See that we found our device:'{self.dut_ble.bt_dut_address}'**********\n\n")

            conn_params = {"min_conn_interval": 40,
                           "max_conn_interval": 40,
                           "conn_latency": 0,
                           "supervision_timeout": 200}
            logger().info("Initiating BLE connection from ble_client2")
            self.ble_client3.interfaces.bluetooth.connect(dev_addr=self.dut_ble.bt_dut_address,
                                                          min_conn_interval=conn_params["min_conn_interval"],
                                                          max_conn_interval=conn_params["max_conn_interval"],
                                                          conn_latency=conn_params["conn_latency"],
                                                          supervision_timeout=conn_params["supervision_timeout"])
            time.sleep(30)
            logger().info(f"\n\n************ble slave connection success**************\n\n")

            logger().info(f"\n\n******Disconnect raspi ble_client from dut*******\n\n")
            self.dut_ble.disconnect(ble1_client_address, timeout=30)
            time.sleep(5)

            logger().info(f"\n\n**********Disconnect raspi ble_client from dut********\n\n")
            self.dut_ble.disconnect(ble2_client_address, timeout=30)
            time.sleep(5)

            logger().info(f"\n\n********Disconnect dut from raspberry*******\n\n")
            self.ble_client3.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)
            time.sleep(5)

            logger().info(f"\n\n********closing ble client1 socket********\n\n")
            self.ble_client1.interfaces.bluetooth.close()
            time.sleep(5)

            logger().info(f"\n\n******closing ble client2 socket*******\n\n")
            self.ble_client2.interfaces.bluetooth.close()
            time.sleep(5)

            logger().info(f"\n\n******closing ble client3 socket********\n\n")
            self.ble_client3.interfaces.bluetooth.close()
            time.sleep(5)
            logger().info(f"\n\n*************iteration : {i}*****************\n\n")

    def multi_2masters_ble_conn_disconn_recon(self):
        no_of_reconnects = 1
        for i in range(no_of_reconnects+1):
            self.dut_ble.start()

            logger().info(f"\n\n*****************start advertising on ble client1****************\n\n")
            ble1_client_address = self.ble_client1.interfaces.bluetooth.start_smp_adv(self.dut_ble.bt_dut_address)
            assert ble1_client_address, "Unable to get ble_client_address"
            logger().info(f"ble client_1 address : {ble1_client_address}")
            time.sleep(1)

            logger().info(f"\n\n***********Start scanning and connect to ble client1**********\n\n")
            self.dut_ble.scan(bt_client_address=ble1_client_address, timeout=120)
            self.dut_ble.scan_stop()
            time.sleep(1)

            logger().info(f"\n\n****************Initiating BLE connection with ble_client1************\n\n")
            self.dut_ble.connect(bt_client_address=ble1_client_address, timeout=120)
            logger().info("BLE Connection success")
            time.sleep(1)

            logger().info(f"\n\n*****************start advertising on ble client2****************\n\n")
            ble2_client_address = self.ble_client2.interfaces.bluetooth.start_smp_adv(self.dut_ble.bt_dut_address)
            assert ble2_client_address, "Unable to get ble_client_address"
            logger().info(f" ble client_2 address : {ble2_client_address}")
            time.sleep(1)

            logger().info(f"\n\n*********Start scanning and connect to ble client2**********\n\n")
            self.dut_ble.scan(bt_client_address=ble2_client_address, timeout=120)
            self.dut_ble.scan_stop()
            time.sleep(1)

            logger().info(f"\n\nInitiating BLE connection with ble_client2\n\n")
            self.dut_ble.connect(bt_client_address=ble2_client_address, timeout=120)
            logger().info("******BLE master Connection success********")
            time.sleep(20)

            logger().info(f"\n\n*****Disconnect raspi ble_client from dut******\n\n")
            self.dut_ble.disconnect(ble1_client_address, timeout=30)
            time.sleep(5)

            logger().info(f"\n\n****Disconnect raspi ble_client from dut******\n\n")
            self.dut_ble.disconnect(ble2_client_address, timeout=30)
            time.sleep(5)

            logger().info(f"\n\n******closing ble client1 socket********\n\n")
            self.ble_client1.interfaces.bluetooth.close()
            time.sleep(5)

            logger().info(f"\n\n*******closing ble client2 socket********\n\n")
            self.ble_client2.interfaces.bluetooth.close()
            time.sleep(5)

            logger().info(f"\n\n**********iteration: {i}**********\n\n")

    def check_connection_stability(self, ble_dut):
        time.sleep(2)
        dis_sta_list = []
        events = ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            if event.event_type == RS9116AsyncEventType.RSI_BLE_DISCONN_EVENT:
                verify_sta_disconnection = event.event_data
                logger().info(f'\n\n Disconnection = {verify_sta_disconnection} \n\n')
                disconnected_node_mac_address = (
                    str(verify_sta_disconnection).split('dev_addr:')[1].split(',')[0].strip())
                dis_sta_list.append(disconnected_node_mac_address)
                logger().info(f'\n\n disconnected sta mac address list= {dis_sta_list}')

    def run(self):
        if self.test_case_no == 18959:
            self.dut_ble.start()
            self.dut_ble.advertise()
            self.dut_ble.scan(ble_scan_type=1, timeout=20)

            time.sleep(5)
            self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)
            time.sleep(5)
            self.respi_ble.scan_stop()

        if self.test_case_no == 18960:
            self.dut_ble.start()
            self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address, smp_adv=True)
            self.dut_ble.scan(bt_client_address=self.respi_ble.bt_client_address, timeout=120)

        if self.test_case_no == 18963:
            service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
            char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
            data1 = "LzY0LzY0LzY0LzY0LzY0"
            if self.verify:
                self.dut_ble.connect(self.respi_ble.bt_client_address)
            else:
                self.dut_ble.start()
                '''Right now these services( 0x1AA1)not available if merge when fix available'''
                self.dut_ble.add_service(uid_name=0x6E)
                self.dut_ble.add_characteristic(uid_name=0x6F)
                self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
                self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address, smp_adv=True)
                time.sleep(5)
                self.dut_ble.scan(bt_client_address=self.respi_ble.bt_client_address, timeout=120)
                time.sleep(2)
                self.dut_ble.connect(self.respi_ble.bt_client_address)
                time.sleep(10)
                logger().info(f'\n\n Remote device will discover services and characteristic of DUT \n\n')
                self.transmit_notification(self.ble_client, service_uid, char_uid, data1, dut_side_notify=True)

                time.sleep(4)
                for i in range(0, 9):
                    logger().info(f'\n\n ***** Connect Disconnect Iteration = {i} ***** \n\n\n')
                    self.dut_ble.disconnect(ble_remote_dev_address=self.respi_ble.bt_client_address)
                    time.sleep(10)
                    self.dut_ble.connect(self.respi_ble.bt_client_address)
                    time.sleep(10)

                while 1:
                    if WlanThread.flag:
                        logger().info(
                            f'\n\n ***** After completing "DISABLE ITERATION" count, again Connect Disconnect '
                            f'operation performed while executing WLAN static sync ***** \n\n\n')
                        self.dut_ble.disconnect(ble_remote_dev_address=self.respi_ble.bt_client_address)
                        self.verify = True
                    break

        if self.test_case_no == 18964:
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address)
            self.dut_ble.scan(bt_client_address=self.respi_ble.bt_client_address, timeout=120)

        if self.test_case_no == 18972:
            self.dut_ble.start()
            self.dut_ble.advertise(ble_adv_int_min=211, ble_adv_int_max=211, timeout=30)
            while 1:
                if WlanThread.flag:
                    self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)
                    time.sleep(10)
                    self.respi_ble.scan_stop()
                    self.dut_ble.advertise_stop()
                    break

        if self.test_case_no == 18974:
            ble_scan_interval = 53
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address, smp_adv=True)
            self.dut_ble.scan(bt_client_address=self.respi_ble.bt_client_address, ble_scan_interval=ble_scan_interval,
                              ble_scan_window=23, timeout=10)
            while 1:
                if WlanThread.flag:
                    self.dut_ble.scan_stop(timeout=15)
                    break

        if self.test_case_no == 18978:
            self.dut_ble.start()
            self.dut_ble.advertise(ble_adv_int_min=211, ble_adv_int_max=211, timeout=30)

            while 1:
                if WlanThread.flag:
                    self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)
                    time.sleep(5)
                    self.dut_ble.advertise_stop()
                    self.respi_ble.scan_stop()
                    break

        if self.test_case_no == 18980:
            ble_scan_interval_value = 3125
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.respi_ble.advertise(bt_dut_address=self.dut_ble.bt_dut_address, smp_adv=True)
            self.dut_ble.scan(bt_client_address=self.respi_ble.bt_client_address,
                              ble_scan_interval=ble_scan_interval_value, timeout=160)
            while 1:
                if WlanThread.flag:
                    self.dut_ble.scan_stop(timeout=20)
                    self.respi_ble.advertise_stop()
                    break

        if self.test_case_no == 18988:
            min_conn_interval = 45
            max_conn_interval = 45
            supervision_timeout = 800
            service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
            char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
            data1 = "LzY0ZLzY0ZLzY0ZLzY0Z"

            self.dut_ble.start()
            '''https://jira.silabs.com/browse/WIFI_BT_UTFHELP-1690 RAVI will update'''
            '''Right now these services( 0x1AA1)not available if merge when fix available'''
            self.dut_ble.add_service(uid_name=0x6E)
            self.dut_ble.add_characteristic(uid_name=0x6F)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
            time.sleep(1)

            logger().info("\n\n ***** Start Adv in DUT(Slave) ***** \n\n\n")
            self.dut_ble.advertise()
            time.sleep(5)

            self.ble_client.interfaces.bluetooth.start_smp_scan(self.dut_ble.bt_dut_address)

            logger().info("Initiating BLE connection")
            logger().info("\n\n ***** Initiating BLE connection from RESPI ***** \n\n\n")
            time.sleep(2)

            self.ble_client.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address,
                                                         min_conn_interval=min_conn_interval,
                                                         max_conn_interval=max_conn_interval,
                                                         supervision_timeout=supervision_timeout)

            assert self.ble_client.interfaces.bluetooth.get_connection_status(self.dut_ble.bt_dut_address)

            time.sleep(2)
            logger().info(f'\n\n Remote device will discover services and characteristic of DUT \n\n')
            self.transmit_notification(self.ble_client, service_uid, char_uid, data1, dut_side_notify=True)

            while 1:
                if WlanThread.flag:
                    self.respi_ble.disconnect(self.dut_ble.bt_dut_address)
                    break

        if self.test_case_no == 18984:
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.dut_ble.advertise()
            bt_client_address = self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)
            logger().info(f"bt_remote_address = {bt_client_address}")

            device_found = False
            sw = Stopwatch()
            while sw.elapsed_sec < 30:
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                if self.dut_ble.bt_dut_address in found_devices and \
                        found_devices[
                            self.dut_ble.bt_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data:
                    device_found = True
                    break

            self.respi_ble.scan_stop()
            assert device_found

            self.respi_ble.connect(self.dut_ble.bt_dut_address)
            time.sleep(5)
            # setting data length on ble_client
            logger().info("Updating ble connection with connection parameters")
            self.ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                dev_addr=self.dut_ble.bt_dut_address,
                connection_handle="0x08 0x0013",
                connection_interval_min="0x46 0x00",
                connection_interval_max="0xA0 0x00",
                max_latency="0xA0 0x00",
                supervision_timeout="0x00 0x00",
                min_ce_length="0x80 0x0c",
                max_ce_length="0x00 0x00",
            )
            time.sleep(60)
            logger().info("======= get connection state")
            state = self.ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"
            logger().info('\n\n ***** BLE DUT is in connected state ***** \n\n')

        if self.test_case_no == 18985:
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.dut_ble.advertise()
            bt_client_address = self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)
            logger().info(f"bt_remote_address = {bt_client_address}")

            device_found = False
            sw = Stopwatch()
            while sw.elapsed_sec < 30:
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                if self.dut_ble.bt_dut_address in found_devices and \
                        found_devices[
                            self.dut_ble.bt_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data:
                    device_found = True
                    break

            self.respi_ble.scan_stop()
            assert device_found
            self.respi_ble.connect(self.dut_ble.bt_dut_address)

            time.sleep(5)

            logger().info("Updating ble connection with connection parameters")
            self.ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                dev_addr=self.dut_ble.bt_dut_address,
                connection_handle="0x08 0x0013",
                connection_interval_min="0x46 0x00",
                connection_interval_max="0xA0 0x00",
                max_latency="0xA0 0x00",
                supervision_timeout="0x00 0x04",
                min_ce_length="0x80 0x0c",
                max_ce_length="0x00 0x00",
            )
            time.sleep(60)
            logger().info("======= get connection state")
            state = self.ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"
            logger().info('\n\n ***** BLE DUT is in connected state ***** \n\n')

        if self.test_case_no == 18986:
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.dut_ble.advertise()
            bt_client_address = self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)
            logger().info(f"bt_remote_address = {bt_client_address}")

            device_found = False
            sw = Stopwatch()
            while sw.elapsed_sec < 30:
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                if self.dut_ble.bt_dut_address in found_devices and \
                        found_devices[
                            self.dut_ble.bt_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data:
                    device_found = True
                    break

            self.respi_ble.scan_stop()
            assert device_found
            self.respi_ble.connect(self.dut_ble.bt_dut_address)

            time.sleep(5)

            logger().info("Updating ble connection with connection parameters")
            self.ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                dev_addr=self.dut_ble.bt_dut_address,
                connection_handle="0x08 0x0013",
                connection_interval_min="0x46 0x00",
                connection_interval_max="0xA0 0x00",
                max_latency="0xA0 0x00",
                supervision_timeout="0x00 0x00",
                min_ce_length="0x80 0x0c",
                max_ce_length="0x00 0x00",
            )
            time.sleep(60)
            logger().info("======= get connection state")
            state = self.ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"
            logger().info('\n\n ***** BLE DUT is in connected state ***** \n\n')

        if self.test_case_no == 18987:
            self.dut_ble.start()
            self.dut_ble.add_service(uid_name=0x180D)
            self.dut_ble.advertise()
            bt_client_address = self.respi_ble.scan(bt_client_address=self.dut_ble.bt_dut_address)
            logger().info(f"bt_remote_address = {bt_client_address}")

            device_found = False
            sw = Stopwatch()
            while sw.elapsed_sec < 30:
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                if self.dut_ble.bt_dut_address in found_devices and \
                        found_devices[
                            self.dut_ble.bt_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data:
                    device_found = True
                    break

            self.respi_ble.scan_stop()
            assert device_found
            self.respi_ble.connect(self.dut_ble.bt_dut_address)
            logger().info("BLE Connection success")
            time.sleep(5)

            logger().info("Updating ble connection with connection parameters")
            self.ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_conn(
                dev_addr=self.dut_ble.bt_dut_address,
                connection_handle="0x08 0x0013",
                connection_interval_min="0x46 0x00",
                connection_interval_max="0xA0 0x00",
                max_latency="0xA0 0x00",
                supervision_timeout="0x00 0x00",
                min_ce_length="0x80 0x0c",
                max_ce_length="0x00 0x00",
            )
            time.sleep(60)
            logger().info("======= get connection state")
            state = self.ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"
            logger().info('\n\n ***** BLE DUT is in connected state ***** \n\n')

        if self.test_case_no == 18971:
            self.multi_client_connection_with_services_notify()
            while 1:
                if WlanThread.flag:
                    self.ble_client1.interfaces.bluetooth.stop_scanning()
                    self.ble_client2.interfaces.bluetooth.stop_scanning()
                    break

        if self.test_case_no == 18973:
            self.multi_client_connection_disconnection_with_services_notify()
            time.sleep(1)
            self.ble_client1.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)
            self.ble_client2.interfaces.bluetooth.disconnect(self.dut_ble.bt_dut_address)
            time.sleep(2)
            # Again trying to connect the DUT
            self.dut_ble.advertise()
            time.sleep(2)

            # Connect BLE client 1 to DUT
            self.ble_client1.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address)

            time.sleep(10)
            self.dut_ble.advertise()
            time.sleep(2)

            # Connect BLE client 2 to DUT
            self.ble_client2.interfaces.bluetooth.connect(self.dut_ble.bt_dut_address)
            while 1:
                if WlanThread.flag:
                    self.ble_client1.interfaces.bluetooth.stop_scanning()
                    self.ble_client2.interfaces.bluetooth.stop_scanning()
                    break

        if self.test_case_no == 18975:
            self.multi_client_connection_with_different_connection_intervals()
            while 1:
                if WlanThread.flag:
                    self.ble_client1.interfaces.bluetooth.stop_scanning()
                    self.ble_client2.interfaces.bluetooth.stop_scanning()
                    break

        if self.test_case_no == 18976:
            self.multi_client_connection_3_with_services_notify()
            while 1:
                if WlanThread.flag:
                    self.ble_client1.interfaces.bluetooth.stop_advertising()
                    self.ble_client2.interfaces.bluetooth.stop_advertising()
                    self.ble_client3.interfaces.bluetooth.stop_advertising()
                    break

        if self.test_case_no == 18982:
            self.multi_client_connection_3_with_services_notify()

            while 1:
                logger().info(f"\n\n **** WLAN Thread = {WlanThread.flag}\n\n\n ****")
                if WlanThread.flag:
                    self.ble_client1.interfaces.bluetooth.stop_advertising()
                    self.ble_client2.interfaces.bluetooth.stop_advertising()
                    self.ble_client3.interfaces.bluetooth.stop_advertising()
                    break

        if self.test_case_no == 18983:
            self.multi_client_connection_5_with_services_notify(no_of_notify_connection=2)
            BleThread.counter_flag = True

        if self.test_case_no == 18939:
            self.multi_client_connection_5_with_services_notify(no_of_notify_connection=2)
            BleThread.counter_flag = True

        if self.test_case_no == 18948:
            self.multi_client_connection_5_with_services_notify(smp_enable_client=True,
                                                                reconnection=True, no_of_notify_connection=2)
            BleThread.counter_flag = True

        if self.test_case_no == 18949:
            self.multi_client_connection_5_with_services_notify(reconnection=True, smp_enable_client=True,
                                                                no_of_notify_connection=2)

            BleThread.counter_flag = True

        if self.test_case_no == 18951:
            ''' Repeat the same test case by changing advertise intervals '''
            interval_list = ['0x06a8 0x00 ', '0x20 0x00 ', '0xa0 0x00 ', '0x4000 0x00 ']
            for ble_adv_interval in interval_list:
                logger().info(f"\n\n ***** ADV INTERVAL = {ble_adv_interval} ***** \n\n\n")
                for i in range(0, self.iterate_count):
                    logger().info(f"\n\n ***** ITERATION COUNT = {i} ***** \n\n\n")
                    self.multi_client_connection_5_with_different_adv_intervals(ble_adv_interval)
                    time.sleep(self.time_period)
                    BleThread.counter_flag = True

            BleThread.execution_flag = False

        if self.test_case_no == 18952:
            ''' Repeat the same test case by changing scan intervals & scan window '''
            scan_param_list = [[33, 14], [150, 100], [550, 500], [150, 20]]
            for values in scan_param_list:
                logger().info(f"\n\n ***** SCAN INTERVAL = {values} ***** \n\n\n")
                for i in range(0, self.iterate_count):
                    self.multi_client_connection_5_with_different_scan_intervals(values[0], values[1])
                    time.sleep(self.time_period)
                    BleThread.counter_flag = True

            BleThread.execution_flag = False

        if self.test_case_no == 18953:
            ''' Repeat the same test case by changing connection intervals '''
            conn_param_list = [250, 45, 200, 100, 325]
            for values in conn_param_list:
                logger().info(f"\n\n ***** CONNECTION INTERVAL = {values} ***** \n\n\n")
                for i in range(0, self.iterate_count):
                    self.multi_client_connection_5_with_different_connection_intervals(values)
                    time.sleep(self.time_period)
                    BleThread.counter_flag = True

            BleThread.execution_flag = False

        if self.test_case_no == 18954:
            ''' Connect & Disconnect of third party BLE devices with DUT'''
            self.multi_client_connection_5_with_services_notify(reconnection=True, no_of_notify_connection=2)
            BleThread.counter_flag = True

            # self.dut_ble.scan_stop()
            # self.dut_ble.advertise_stop()
            # self.ble_client1.interfaces.bluetooth.stop_advertising()
            # self.ble_client2.interfaces.bluetooth.stop_advertising()
            # self.ble_client3.interfaces.bluetooth.stop_advertising()

        if self.test_case_no == 18956:
            ''' Repeat the same test case by changing advertise intervals '''
            self.multi_client_connection_5_with_services_notify(reconnection=False, no_of_notify_connection=5)
            BleThread.counter_flag = True

            # self.dut_ble.scan_stop()
            # self.dut_ble.advertise_stop()
            # self.ble_client1.interfaces.bluetooth.stop_advertising()
            # self.ble_client2.interfaces.bluetooth.stop_advertising()
            # self.ble_client3.interfaces.bluetooth.stop_advertising()


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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_scan_dut_ble_adv_respi_scan_c18959(wifi_dut, wifi_access_point, ble_dut, ble_client, rs_helper_ble,
                                                 request):
    test_case_no = 18959
    '''Test DUT BLE advertisement + Remote BLE scan and Wi-Fi scan'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                                enable_smp=0)

            wlan_obj.start()
            ble_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_ble_scan_c18960(wifi_dut, wifi_access_point, ble_dut, ble_client, rs_helper_ble, request):
    test_case_no = 18960

    '''Test BLE scan and Wi-Fi scan'''
    '''This test case will be failed in shield box '''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18959)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                                enable_smp=0)

            wlan_obj.start()
            ble_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_ble_reconnection_c18963(wifi_dut, wifi_access_point, ble_dut, ble_client, http_server, http_client,
                                           index_path, rs_helper_ble, request):
    test_case_no = 18963
    iterate_count = 5
    '''JIRA filed https://jira.silabs.com/browse/WIFI_BT_UTFHELP-1775'''
    '''Wi-Fi sync(transient) + 1 BLE phone connection and reconnection'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                                iterate_count=iterate_count, enable_smp=0)

            wlan_obj.start()
            ble_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
            # wlan_obj.start()
            # wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address,
                                  ble_remotes={ble_client: 8})
        wifi_dut.interfaces.wifi.leave()


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
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_connect_ble_scan_c18964(wifi_dut, wifi_access_point, ble_dut, ble_client, rs_helper_ble, request):
    test_case_no = 18964
    '''WIFI Connected and BLE scan'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                                enable_smp=0)

            wlan_obj.start()
            ble_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()
        time.sleep(20)


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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_scan_ble_advertise_c18972(wifi_dut, wifi_access_point, ble_dut, ble_client, rs_helper_ble, request):
    test_case_no = 18972
    iterate_count = 10
    '''WiFi Scan Coex Static Test with BLE advertise'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no,
                                  iterate_count=iterate_count)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                                iterate_count=iterate_count, enable_smp=0)

            wlan_obj.start()
            ble_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
            # time.sleep(20)
            # wlan_obj.start()
            # wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_scan_ble_advertise_c18974(wifi_dut, wifi_access_point, ble_dut, ble_client, rs_helper_ble, request):
    test_case_no = 18974
    iterate_count = 50
    '''WiFi Scan Coex Static Test while BLE scan'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18972,
                                  iterate_count=iterate_count)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                                enable_smp=0)

            wlan_obj.start()
            ble_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
            time.sleep(15)
            wlan_obj.start()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_ble_advertise_c18978(wifi_dut, wifi_access_point, ble_dut, ble_client, http_server, http_client,
                                        index_path, rs_helper_ble, request):
    test_case_no = 18978
    iterate_count = 10
    '''WiFi Sync Coex Static Test while BLE advertise'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                                iterate_count=iterate_count)

            wlan_obj.start()
            ble_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_ble_scan_c18980(wifi_dut, wifi_access_point, ble_dut, ble_client, http_server, http_client,
                                   index_path, rs_helper_ble, request):
    test_case_no = 18980
    iterate_count = 1
    '''WiFi Sync Coex Static Test while BLE scan'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no
                                , enable_smp=0)

            wlan_obj.start()
            ble_obj.start()
            wlan_obj.wait_for_exit()
            ble_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_ble_stability_scan_c18988(wifi_dut, wifi_access_point, ble_dut, ble_client, http_server, http_client,
                                             index_path, rs_helper_ble, request):
    test_case_no = 18988
    iterate_count = 10
    '''Test BLE phone connection stability while Wi-Fi sync when BLE device is connected first'''
    '''https://jira.silabs.com/browse/WIFI_BT_UTFHELP-1690 RAVI will update'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")

            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                                enable_smp=1)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_ble_slave_latency_c18984(wifi_dut, wifi_access_point, ble_dut, ble_client, index_path,
                                            http_server, http_client, rs_helper_ble, request):
    test_case_no = 18984
    iterate_count = 1
    '''Verify Slave latency functionality when remote master update connection params with 0 slave latency while 1MB
        file download through HTTP'''

    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18961,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                                iterate_count=iterate_count)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient |
                               RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_1mb_file_ble_slave_latency_c18985(wifi_dut, wifi_access_point, ble_dut, ble_client, index_path,
                                                     http_server, http_client, rs_helper_ble, request):
    test_case_no = 18985
    iterate_count = 1
    '''Verify Slave latency functionality when remote master update connection params with slave latency field with 
    values between 1 to ((LSTO / (CIMax*2)) -1) while 1MB file download through HTTP'''

    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18961,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                                iterate_count=iterate_count)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"10MB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_10mb_file_ble_slave_latency_c18986(wifi_dut, wifi_access_point, ble_dut, ble_client, index_path,
                                                      http_server, http_client, rs_helper_ble, request):
    test_case_no = 18986
    iterate_count = 1
    '''Verify Slave latency functionality when remote master update connection params with slave latency field out of 
    the range while 10MB file download through HTTP '''

    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
        "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_1mb_file_ble_slave_latency_c18987(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client,
                                                     index_path, http_server, http_client, rs_helper_ble, request):
    test_case_no = 18987
    iterate_count = 1
    '''Verify Slave latency functionality when remote master update connection params with slave latency field with 
    values between 1 to ((LSTO / (CIMax*2)) -1) while 1MB file download through HTTPS'''

    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18961,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
def test_wlan_scan_ble_2_connection_c18971(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client, ble_clients,
                                           rs_helper_ble, request, utf_constants):
    test_case_no = 18971
    iterate_count = 50
    remote_devices_count = 2
    '''WiFi Scan Coex Static connection test with 2 phones'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18972,
                                  iterate_count=iterate_count)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, test_case_no=test_case_no, ble_clients=ble_clients,
                                remote_devices_count=remote_devices_count, utf_constants=utf_constants)

            wlan_obj.start()
            ble_obj.start()
            wlan_obj.wait_for_exit()
            ble_obj.wait_for_exit()
            wlan_obj.start()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
def test_wlan_scan_ble_2_connection_c18973(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client, ble_clients,
                                           request, rs_helper_ble, utf_constants):
    test_case_no = 18973
    iterate_count = 50
    remote_devices_count = 2
    '''WiFi Scan Coex transient test with two BLE phones connection'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18972,
                                  iterate_count=iterate_count)
            ble_obj = BleThread(wifi_dut=wifi_dut, test_case_no=test_case_no, ble_dut=ble_dut, ble_clients=ble_clients,
                                remote_devices_count=remote_devices_count, utf_constants=utf_constants)

            wlan_obj.start()
            ble_obj.start()
            wlan_obj.wait_for_exit()
            ble_obj.wait_for_exit()
            wlan_obj.start()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
def test_wlan_scan_ble_2_connection_c18975(wifi_dut, wifi_sniffer, wifi_access_point, ble_dut, ble_client, ble_clients,
                                           request, rs_helper_ble, utf_constants):
    test_case_no = 18975
    iterate_count = 50
    remote_devices_count = 2
    '''WiFi Scan Coex Static Test while BLE phones conn update'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18972,
                                  iterate_count=iterate_count)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, test_case_no=test_case_no, ble_clients=ble_clients,
                                remote_devices_count=remote_devices_count, utf_constants=utf_constants)

            wlan_obj.start()
            ble_obj.start()
            wlan_obj.wait_for_exit()
            ble_obj.wait_for_exit()
            wlan_obj.start()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_static_ble_2_connection_c18977(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients, index_path,
                                             http_server, http_client, request, rs_helper_ble, utf_constants):
    iterate_count = 5
    remote_devices_count = 2
    '''WiFi Sync Coex Static Test while 2 BLE connections'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, test_case_no=18971, ble_dut=ble_dut, ble_client=ble_client,
                                ble_clients=ble_clients, remote_devices_count=remote_devices_count,
                                utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
            wlan_obj.start()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_transient_sync_ble_2_connection_c18979(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients,
                                                     index_path, http_server, http_client, request, rs_helper_ble,
                                                     utf_constants):
    iterate_count = 10
    remote_devices_count = 2

    '''WiFi Sync Coex transient test while 2 remote central connections'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, test_case_no=18973, ble_dut=ble_dut, ble_client=ble_client,
                                ble_clients=ble_clients, remote_devices_count=remote_devices_count,
                                utf_constants=utf_constants)

            wlan_obj.start()
            ble_obj.start()
            wlan_obj.wait_for_exit()
            ble_obj.wait_for_exit()
            wlan_obj.start()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_static_sync_ble_2_connection_c18981(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients,
                                                  index_path, http_server, http_client, request, rs_helper_ble,
                                                  utf_constants):
    iterate_count = 10
    remote_devices_count = 2
    '''WiFi Sync Coex Static Test while two BLE phones conn params update'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, test_case_no=18975, ble_dut=ble_dut, ble_client=ble_client,
                                ble_clients=ble_clients, remote_devices_count=remote_devices_count,
                                utf_constants=utf_constants)

            wlan_obj.start()
            ble_obj.start()
            wlan_obj.wait_for_exit()
            ble_obj.wait_for_exit()
            wlan_obj.start()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
def test_wlan_scan_ble_3_connection_c18976(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients, request,
                                           rs_helper_ble, utf_constants):
    test_case_no = 18976
    iterate_count = 5
    remote_devices_count = 3
    '''WiFi Scan Coex Static Test while 3 phone connections'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18972,
                                  iterate_count=iterate_count)
            ble_obj = BleThread(wifi_dut=wifi_dut, test_case_no=test_case_no, ble_dut=ble_dut, ble_client=ble_client,
                                ble_clients=ble_clients, remote_devices_count=remote_devices_count,
                                utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
            wlan_obj.start()
            wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_ble_3_connection_c18982(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients, index_path,
                                           http_server, http_client, request, rs_helper_ble, utf_constants):
    test_case_no = 18982
    iterate_count = 5
    remote_devices_count = 3
    '''WiFi Sync Coex Static Test after 3 phones connection'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, test_case_no=test_case_no,
                                ble_clients=ble_clients, iterate_count=iterate_count,
                                remote_devices_count=remote_devices_count, utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
            time.sleep(20)
            wlan_obj.start()
            wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_dut.interfaces.bluetooth.close()
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_ble_5_connection_c18983(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients, index_path,
                                           http_server, http_client, request, rs_helper_ble, utf_constants):
    test_case_no = 18983
    remote_devices_count = 5
    '''Wi-Fi HTTP Continues Download, BLE advertising (0x152 interval) +BLE two peripheral connection (45ms CI)'''
    try:

        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no,
                                  http_server=http_server, http_client=http_client, index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, ble_clients=ble_clients,
                                test_case_no=test_case_no, remote_devices_count=remote_devices_count,
                                utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_ble_5_connection_c18939(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients, index_path,
                                           http_server, http_client, request, rs_helper_ble, utf_constants):
    test_case_no = 18983
    remote_devices_count = 5
    '''Test Wi-Fi connection with different character types(@#$%^) and 32bytes length of SSID along with 5 BLE 
        connections'''
    wifi_access_point.interfaces.wifi.config['ssid'] = '#@$!%#@$!%#@$!%#@$!%abcdefghijkl'
    wifi_access_point.interfaces.wifi.start_ap()
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no,
                                  http_server=http_server, http_client=http_client, index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, ble_clients=ble_clients,
                                test_case_no=test_case_no, remote_devices_count=remote_devices_count,
                                utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_sync_ble_5_connection_c18940(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients, index_path,
                                           http_server, http_client, request, rs_helper_ble, utf_constants):
    test_case_no = 18983
    remote_devices_count = 5
    '''Test Wifi connection with max passphrase character(64) with BLE connection'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            wifi_access_point.interfaces.wifi.config[
                'passphrase'] = '123456789012345678901234567890123456789012345678901234567890123'
            time.sleep(2)
            wifi_access_point.interfaces.wifi.start_ap()
            time.sleep(60)

            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no,
                                  http_server=http_server, http_client=http_client, index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, ble_clients=ble_clients,
                                test_case_no=test_case_no, remote_devices_count=remote_devices_count,
                                utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp
                           | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_static_sync_ble_5_connection_c18942(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients,
                                                  http_server, http_client, request, rs_helper_ble, index_path,
                                                  utf_constants):
    remote_devices_count = 5
    iterate_count = 5
    '''Test Wi-Fi connect and disconnect with 5 BLE connections'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18963,
                                  http_server=http_server, http_client=http_client, index_path=index_path,
                                  iterate_count=iterate_count)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, ble_clients=ble_clients,
                                test_case_no=18983, remote_devices_count=remote_devices_count,
                                utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp
                           | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_static_sync_ble_5_connection_c18944(wifi_dut, wifi_access_point, ble_dut, ble_client, ble_clients,
                                                  request, utf_constants, rs_helper_ble):
    remote_devices_count = 5
    '''Get the list of ap's scanned before wifi connection'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18944)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, ble_clients=ble_clients,
                                test_case_no=18983, remote_devices_count=remote_devices_count,
                                utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp
                           | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_static_sync_ble_5_connection_c18947(wifi_dut, wifi_access_point, ble_dut, ble_client,
                                                  index_path, http_server, http_client, request, ble_clients,
                                                  rs_helper_ble, utf_constants):
    remote_devices_count = 5
    iterate_count = 20
    '''Enable SMP for 5 BLE connections with IO capability Display Only and connect the third party BLE devices while 
       WiFi HTTP data transfer '''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18947,
                                  iterate_count=iterate_count, http_server=http_server, index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, enable_smp=1, ble_dut=ble_dut, ble_client=ble_client,
                                ble_clients=ble_clients, test_case_no=18983, remote_devices_count=remote_devices_count,
                                utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient |
                               RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_connection_disconnection_ble_5_connection_c18948(wifi_dut, wifi_access_point, ble_dut, ble_client,
                                                               index_path, http_server, http_client, ble_clients,
                                                               request, rs_helper_ble, utf_constants):
    remote_devices_count = 5
    iterate_count = 50
    '''Enable SMP for only masters2 RESPI) and verify connection & disconnection while wi-fi HTTP data transfer'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18983,
                                  iterate_count=iterate_count, http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client,
                                ble_clients=ble_clients, test_case_no=18948, remote_devices_count=remote_devices_count,
                                utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.skip
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient |
                               RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_smp_slave_connection_disconnection_ble_5_connection_c18949(wifi_dut, wifi_access_point, ble_dut,
                                                                         ble_client, index_path, http_server,
                                                                         http_client, ble_clients, request,
                                                                         rs_helper_ble, utf_constants):
    remote_devices_count = 5
    test_case_no = 18949
    '''Enable SMP only for slaves and verify connection and disconnection while wifi HTTP data transfer'''
    '''0x4E3D Connection terminated due to MIC failure'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18983,
                                  http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, enable_smp=1, ble_dut=ble_dut, ble_client=ble_client,
                                ble_clients=ble_clients, test_case_no=test_case_no,
                                remote_devices_count=remote_devices_count, utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_advertisement_intervals_ble_5_connection_c18951(wifi_dut, wifi_access_point, ble_dut, ble_client,
                                                              ble_clients, index_path, http_server, http_client,
                                                              utf_constants, request, rs_helper_ble):
    remote_devices_count = 5
    test_case_no = 18951

    '''Test co-ex functionality by changing adv min & max values and initiate BLE connections while wi-fi HTTP data 
        transfer'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            time_period = utf_constants.get("time_period")
            logger().info(f'\n\n ***** Time duration for stability = {time_period}\n\n')

            iteration_count = utf_constants.get("iteration_count")
            logger().info(
                f'\n\n ***** Test Iteration count for each Advertise interval for all devices = {iteration_count}\n\n')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=test_case_no,
                                  http_server=http_server, http_client=http_client, index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, ble_clients=ble_clients,
                                test_case_no=test_case_no, remote_devices_count=remote_devices_count,
                                time_period=time_period, iterate_count=iteration_count, utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_scan_intervals_ble_5_connection_c18952(wifi_dut, wifi_access_point, ble_dut, ble_client,
                                                     ble_clients, index_path, http_server, http_client, utf_constants,
                                                     request, rs_helper_ble):
    remote_devices_count = 5
    test_case_no = 18952

    '''Test Coex functionality by changing scan intervals and initiate BLE connection with wi-fi connection while 
       HTTP data transfer.'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            time_period = utf_constants.get("time_period")
            logger().info(f'\n\n ***** Time duration for stability = {time_period}\n\n')

            iteration_count = utf_constants.get("iteration_count")
            logger().info(
                f'\n\n ***** Test Iteration count for each Advertise interval for all devices = {iteration_count}\n\n')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18951,
                                  http_server=http_server, http_client=http_client, index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, ble_clients=ble_clients,
                                test_case_no=test_case_no, remote_devices_count=remote_devices_count,
                                time_period=time_period, iterate_count=iteration_count, utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_connection_intervals_ble_5_connection_c18953(wifi_dut, wifi_access_point, ble_dut, ble_client,
                                                           ble_clients, index_path, http_server, http_client,
                                                           utf_constants, request, rs_helper_ble):
    remote_devices_count = 5
    test_case_no = 18953

    '''Test coex functionality by changing connection interval parameters from min to max and initiate BLE connection 
       while wifi HTTP data transfer.'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            time_period = utf_constants.get("time_period")
            logger().info(f'\n\n ***** Time duration for stability = {time_period}\n\n')

            iteration_count = utf_constants.get("iteration_count")
            logger().info(
                f'\n\n ***** Test Iteration count for each Advertise interval for all devices = {iteration_count}\n\n')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18951,
                                  http_server=http_server, http_client=http_client, index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, ble_clients=ble_clients,
                                test_case_no=test_case_no, remote_devices_count=remote_devices_count,
                                time_period=time_period, iterate_count=iteration_count, utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_connect_disconnect_ble_5_connection_c18954(wifi_dut, wifi_access_point, ble_dut, ble_client,
                                                         ble_clients, index_path, http_server, http_client,
                                                         utf_constants, request, rs_helper_ble):
    remote_devices_count = 5
    test_case_no = 18954
    '''Test connect & disconnect of third party BLE devices with DUT and Wifi HTTP data transfer should happen.'''
    ''' Observed scaning failure after connection '''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            iteration_count = utf_constants.get("iteration_count")
            logger().info(
                f'\n\n ***** Test Iteration count for each Advertise interval for all devices = {iteration_count}\n\n')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18983,
                                  http_server=http_server, http_client=http_client,
                                  index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client,
                                ble_clients=ble_clients, test_case_no=test_case_no, iterate_count=iteration_count,
                                remote_devices_count=remote_devices_count, utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


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
@pytest.mark.parametrize("index_path", {"6KB.htm"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_advertisement_intervals_ble_5_connection_c18956(wifi_dut, wifi_access_point, ble_dut, ble_client,
                                                              ble_clients, index_path, http_server, http_client,
                                                              utf_constants, request, rs_helper_ble):
    remote_devices_count = 5
    test_case_no = 18956

    '''Enable notifications for all the 5 BLE connections and verify wi-fi connection along with HTTP download'''
    try:
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_{test_name}.log_{int(time.time())}"):
            logger().info("checking whether server is running....")
            server_stat = http_server.interfaces.http.started
            assert server_stat is True
            logger().info(f'http server state is {server_stat}')

            time_period = utf_constants.get("time_period")
            logger().info(f'\n\n ***** Time duration for stability = {time_period}\n\n')

            iteration_count = utf_constants.get("iteration_count")
            logger().info(
                f'\n\n ***** Test Iteration count for each Advertise interval for all devices = {iteration_count}\n\n')

            wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18983,
                                  http_server=http_server, http_client=http_client, index_path=index_path)
            ble_obj = BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client, ble_clients=ble_clients,
                                test_case_no=test_case_no, remote_devices_count=remote_devices_count,
                                time_period=time_period, iterate_count=iteration_count, utf_constants=utf_constants)

            ble_obj.start()
            wlan_obj.start()
            ble_obj.wait_for_exit()
            wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()
