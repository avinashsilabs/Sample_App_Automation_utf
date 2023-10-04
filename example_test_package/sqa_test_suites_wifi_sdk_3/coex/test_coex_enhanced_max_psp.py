import re
import time
from utf.utils.time_measurer import TimeMeasurer
from example_test_package.sqa_test_suites_wifi_sdk_3.test_wlan_data_rates_sdk import SocketDataTransfer
import pytest as pytest
from utf import UtfDatabaseProperties
from utf.utils.iperf.iperf_utils import ping
import threading
from threading import Thread, Event
from utf.utils.thread_base import ThreadBase
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.shell.ssh_shell import SSHShell
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
    Si91xCertificateType
)
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.iperf.iperf_utils import print_dict, ping
from utf.interfaces.iperf.iperf_device_output_parser import Result
from numpy import arange
from utf.utils.thread_base import ThreadBase


def logger():
    return get_logger(__name__)


"""Author : Vivek"""

"""This test plan runs below test steps for validation of DUT-Si91x for Enhanced max psp.
        1. Configuration of DUT in 2G : BGN
        2. Configure AP as per test case requirement(DTIM/Beacon interval)
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Verification of basic power save/pm bit enable or not
        6. Validation of DTIM interval/Listen Interval/Monitor interval.
        7. Validation of power save with Coax(WLAN+BT+BLE) mode with different combination like BT/BLE(Master/Slave) mode.
        8. Validation of power save in Coax(WLAN+BT)/(WLAN+BLE) traffic.
        9. Validation of power save in Coax(WLAN+BT)/(WLAN+BLE) traffic while WLAN connected in 5G mode.
        10.Validation of power save in Coax(WLAN+BT)/(WLAN+BLE) with BT/BLE connect-disconnect multiple times.  

    setup requirement:
        1. DUT(Si91x)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's-ASUS-RTAX3000)
        5. Sniffer(NUC device)
"""


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


class BleThreadDisconnection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, ble_cli_add):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.self.bt_client_address = ble_cli_add

    def run(self):
        time.sleep(10)
        self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.self.bt_client_address, timeout=30)


class BleThreadConnection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode=True):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode
        self.ble_cli_add = None

        if self.mode:
            # Start DUT BLE as a Master
            self.logger.info('***** DUT BLE as a Master *****')
            self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            time.sleep(5)
            assert self.bt_dut_address is not None

            # # Start ble client(Raspberry)
            self.self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=self.bt_dut_address)
            self.ble_cli_add = self.self.bt_client_address
            assert self.self.bt_client_address is not None

            # Start scanning and connect to ble client
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.self.bt_client_address, timeout=15)
            time.sleep(10)

        elif self.mode is False:
            self.logger.info('***** DUT BLE as a Slave *****')
            # Set up DUT for BLE advertising
            self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert self.bt_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            # Begin Scanning for BLE devices
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=self.bt_dut_address)
            assert self.bt_client_address is not None
            time.sleep(3)
            self.ble_client.interfaces.bluetooth.stop_scanning()

            # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            self.ble_cli_add = self.bt_client_address
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (
                    found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                    == self.wifi_dut.interfaces.wifi.ble_advertising_data
            )

    def run(self):
        if self.mode:
            self.logger.info('***** DUT BLE as a Master *****')
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=self.self.bt_client_address, timeout=30)

        elif self.mode is False:
            self.logger.info('********* DUT BLE as a Slave **********')
            self.ble_client.interfaces.bluetooth.connect(self.bt_dut_address)


class BleThreadConnectionDataTransfer(ThreadBase):
    def __init__(self, wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client

    def run(self):
        if not isinstance(self.wifi_dut.interfaces.wifi, RSSAPICommands):
            raise NotImplementedError(
                "This test case is only currently implemented for SAPI"
            )

        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        data1 = "LzY0"
        data2 = "K09x"
        data3 = "Mx3Y"

        # Join Wi-Fi Access Point
        # self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)

        # Set up BLE Server on DUT
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()

        # Set up BLE Server on DUT
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

        # Start advertising
        self.wifi_dut.interfaces.wifi.ble_start_advertising()

        # Begin Scanning for BLE devices
        self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert self.bt_client_address is not None

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            if bt_dut_address in found_devices and \
                    found_devices[bt_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data:
                device_found = True
                break

        self.ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found

        # connecting to dut
        self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(2)

        # resolving charecteristic
        servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0
        assert len(chars) > 0

        char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                         service_uid=service_uid,
                                                                                                         char_uid=char_uid)
        assert char_path is not None
        assert len(char_props) > 0

        # read value - Notifications not enabled
        result = self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        assert result == data1

        # subscribe to notifications
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                     char_uid=char_uid)

        # notify only
        self.wifi_dut.interfaces.wifi.ble_notify_value()

        # write/read new value - Notifications enabled
        self.ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data2)
        time.sleep(0.1)
        result = self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        assert result == data2

        # write value - Notifications enabled
        self.ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data3)

        # auto notify
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                     char_uid=char_uid)
        self.wifi_dut.interfaces.wifi.ble_start_notify_value(interval_ms=500, count=2)
        time.sleep(1)

        # subscribe to notifications
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        time.sleep(1)
        # notify only - disabled notifications - should raise exception
        with pytest.raises(WlanError) as exc_info:
            self.wifi_dut.interfaces.wifi.ble_notify_value()
        assert exc_info.value.error_code == 0x21 or exc_info.value.error_code == 0xFFFFFFFD

        # assert received notifications
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        logger().info(notifications)
        assert len(notifications) == 6
        assert notifications[0] == data1
        assert notifications[1] == data2
        assert notifications[2] == data2
        assert notifications[3] == data3
        assert notifications[4] == data3
        assert notifications[5] == data3

        # disconnecting from dut
        self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


class BleThreadConnectionDisconnection(ThreadBase):
    def __init__(self, wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.connect_disconnect_obj = FilterPacket()

    def run(self):
        self.connect_disconnect_obj.test_ble_multi_connect_disconnect(self.wifi_dut, self.ble_client)


class WifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, net_perf_client=None, protocol=None, wifi_sniffer=None,
                 test_case_name=None, test_case_no=None, sl_collections=None):
        super().__init__()
        self.iperf_obj = FilterPacket()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.dut_addr = None
        self.protocol = protocol
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_case_no = test_case_no
        self.test_case_name = test_case_name
        self.mode = None
        self.dtim_aligned_type = None
        self.num_of_dtim_skip = num_of_dtim_skip
        self.listen_interval = listen_interval

    def run(self):
        if self.test_case_no == 34469:
            transfer_type = 1,
            protocol = 6,
            throughput_type = 3,
            size = 1460
            self.mode = "power_save_low_latency"
            self.dtim_aligned_type = 0
            self.num_of_dtim_skip = 0
            self.listen_interval = 1100

        if self.test_case_no == 34474:
            transfer_type = 1,
            protocol = 6,
            throughput_type = 3,
            size = 1460
            self.mode = "power_save_low_latency"
            self.dtim_aligned_type = 0
            self.num_of_dtim_skip = 0
            self.listen_interval = 1100

        if self.test_case_no == 34475:
            transfer_type = 1,
            protocol = 6,
            throughput_type = 3,
            size = 1460
            self.mode = "power_save_low_latency"
            self.dtim_aligned_type = 0
            self.num_of_dtim_skip = 0
            self.listen_interval = 1100

        if self.test_case_no == 34476:
            transfer_type = 1,
            protocol = 6,
            throughput_type = 3,
            size = 1460
            self.mode = "power_save_low_latency"
            self.dtim_aligned_type = 0
            self.num_of_dtim_skip = 0
            self.listen_interval = 1100

        if self.test_case_no == 34477:
            transfer_type = 1,
            protocol = 6,
            throughput_type = 3,
            size = 1460
            self.mode = "power_save_low_latency"
            self.dtim_aligned_type = 0
            self.num_of_dtim_skip = 0
            self.listen_interval = 1100

        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case_name)
        self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                 wifi_access_point=self.wifi_access_point,
                                                                 mode=self.mode,
                                                                 dtim_aligned_type=self.dtim_aligned_type,
                                                                 num_of_dtim_skip=self.num_of_dtim_skip,
                                                                 listen_interval=self.listen_interval)
        logger().info("DUT successfully connected with AP")
        time.sleep(2)

        # server_ip = str(self.net_perf_client.interfaces.net_perf.host_ip)
        # self.wifi_dut.interfaces.wifi.ping(
        #     server_ip=str(self.net_perf_client.interfaces.net_perf.host_ip)
        # )
        # logger().info(f"HOST IP = {server_ip}")
        # host_ip = "192.168.50.212"
        #
        # self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
        # self.dut_addr['device_ip'], protocol=self.protocol)
        #
        # self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
        #                                     local_port=self.net_perf_client.interfaces.net_perf.client_port,
        #                                     local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
        #                                     remote_port=self.net_perf_client.interfaces.net_perf.client_port,
        #                                     size=size, ttl=30, throughput_type=throughput_type, qos=0)
        # logger().info("data received is successful")
        ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
        self.iperf_obj.start_iperf_dut_as_server(self.wifi_dut, self.net_perf_client, self.protocol,
                                                 self.dut_addr['device_ip'], sl_collections=self.sl_collections)


class WifiPingThread(ThreadBase):
    def __init__(self, wifi_dut, device_ip):
        super().__init__()
        self.device_ip = device_ip

    def run(self):
        # Initiate ping from third party wifi-client to DUT
        ping(self.device_ip, 150)
        time.sleep(10)


class AccessPointApOnOff(ThreadBase):
    def __init__(self, wifi_access_point):
        super().__init__()
        self.wifi_access_point = wifi_access_point

    def run(self):
        logger().info('******* Disable the AP radio **********')
        self.wifi_access_point.interfaces.wifi.stop_ap()
        logger().info('******* Enable the AP radio **********')
        self.wifi_access_point.interfaces.wifi.start_ap()


class FilterPacket:
    def __init__(self):
        self.bt_client_address = None

    def delta_between_ps_poll_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff_list = []

        '''This function is responsible to create a list for PS-Poll packet time delta between 12 consecutive beacon '''

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                if (time_delta_from_previous_packet >= str(1)) and (time_delta_from_previous_packet <= str(2)):
                    logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                    time_diff_list.append(float(time_delta_from_previous_packet))

        filter_file.close()
        return time_diff_list

    def parse_sniffer_packets(self):
        packet_type = "    Type/Subtype:"
        packet_filter_frame = '    Frame Number:'
        packet_filter_beacon = '    Type/Subtype: Beacon frame (0x0008)'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        sniffer_dict = dict()

        """This function takes the filter2_file.txt as a input and parse all captured sniffer packet and convert into 
        dictionary as per given input"""
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if packet_filter_frame in line:
                frame_num = line.split(':')[1].strip()

            if packet_type in line:
                if packet_filter_beacon.strip() == line.strip():
                    sniffer_dict[frame_num] = 'beacon'
                if packet_filter_ps_poll.strip() == line.strip():
                    sniffer_dict[frame_num] = 'PS-Poll'
                if packet_filter_data.strip() == line.strip():
                    sniffer_dict[frame_num] = 'Data'
        logger().info("---------Printing sniffer parse dictionary------------\n")
        # logger().info(sniffer_dict)
        return sniffer_dict

    def match_packet_sequence(self, sniffer_dict):
        ps_status = False
        data_status = False
        ps_key = 0
        data_key = 0
        count = 0
        """This function validates the packet sequence for DTIM count reaches 0(As per test case requirement need to validate 
        Beacon-> Ps-Poll-> Data packets sequentially"""

        for key, value in sniffer_dict.items():
            # logger().info(key, '=', value)
            if value == 'beacon':
                beacon_key = key
            if value == 'PS-Poll':
                # logger().info(key, '=', value)
                if int(key) == int(beacon_key) + 1:
                    ps_key = key
                    ps_status = True
                else:
                    ps_status = False
            if value == 'Data':
                # logger().info(key, '=', value)
                if int(key) == int(ps_key) + 1:
                    data_key = key
                    data_status = True
                else:
                    data_status = False
            if ps_status and data_status:
                # logger().info(ps_status, data_status)
                logger().info(f'Sequence of TIM Beacon frame = {beacon_key}, PS-Poll = {ps_key}, Data = {data_key}\n')
                ps_status = False
                data_status = False
                count = count + 1

        return False if count == 0 else True

    def parse_sniffer_packet_more_data(self):
        packet_type = "    Type/Subtype:"
        packet_filter_frame = '    Frame Number:'
        packet_filter_beacon = '    Type/Subtype: Beacon frame (0x0008)'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        packet_filter_more_data_enable = '            ..1. .... = More Data: Data is buffered for STA at AP'
        packet_filter_more_data_disable = '            ..0. .... = More Data: No data buffered'

        sniffer_dict = dict()
        frame_num = 0
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if packet_filter_frame in line:
                frame_num = line.split(':')[1].strip()
            if packet_type in line:
                if packet_filter_ps_poll.strip() == line.strip():
                    sniffer_dict[frame_num] = 'PS-Poll'
            if packet_filter_more_data_enable in line:
                sniffer_dict[frame_num] = 'More Data'
            if packet_filter_more_data_disable in line:
                sniffer_dict[frame_num + 'N'] = 'No Data'
            if packet_filter_beacon in line:
                sniffer_dict[frame_num] = 'beacon'

        filter_file.close()
        # logger().info("---------Printing sniffer parse dictionary------------\n")
        # logger().info(sniffer_dict)
        return sniffer_dict

    def validate_data_packet_with_more_bit_enable(self, sniffer_dict):
        ps_status = False
        no_more_data_status = False
        beacon_status = False
        ps_key = 0
        more_key = 0
        beacon_key = 0
        no_more_data_key = 0
        status_more_data = 0
        status_beacon = 0
        more_key_status = False
        status = True

        for key, value in sniffer_dict.items():
            if value == 'More Data' or ((value == 'More Data') and (int(key) == int(ps_key) + 1)):
                more_key = key
                more_key_status = True
            if value == 'PS-Poll':
                if (int(key) == int(more_key) + 1) and (more_key_status is True):
                    ps_key = key
                    ps_status = True
            if (value == 'No Data') and (key == str(ps_key) + 'N'):
                # this is More data filed 0 belongs to PS-Poll packet no wouldn't count
                pass
            if (value == 'No Data') and (key != str(ps_key) + 'N'):
                # this is Qos data packet with More data filed 0 and we are expecting next packet should be beacon
                no_more_data_key = key
                no_more_data_status = True
            if (value == 'beacon') and (no_more_data_status is True):
                # Verifying whether beacon packet is next to QoS Data with More bit 0
                if int(key) == int(no_more_data_key.split('N')[0]) + 1:
                    beacon_key = key
                    beacon_status = True

            if more_key_status is True and ps_status is True:
                # if Qos Data with More data bit 1 and Ps-Poll packet comes consecutively then pass the test case
                logger().info(f'Qos Data with More data 1 = {more_key}, PS-Poll = {ps_key}')
                ps_status = False
                more_key_status = False
                status_more_data = status_more_data + 1

            if beacon_status:
                # if Qos Data with More data bit 0 and Beacon packet comes consecutively then pass the test case
                logger().info(f'Qos Data with More data 0 = {no_more_data_key}, Beacon = {beacon_key}')
                beacon_status = False
                no_more_data_status = False
                status_beacon = status_beacon + 1

        if status_beacon == 0:
            logger().info(f'Expecting Beacon after Data packet with More bit value 0(QoS + More data bit 0 -> Beacon')
            status = False
        if status_more_data == 0:
            logger().info(f'Expecting PS-Poll after Data packet with More bit enable(QoS + More data bit 1 -> Ps-Poll)')
            status = False
        return status

    def parse_sniffer_packet_for_max_psp_95(self):
        packet_filter_frame = '    Frame Number:'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        packet_filter_dtim0 = '            DTIM count: 0'

        """This function takes the filter2_file.txt as a input and parse all captured sniffer packet and convert into
        dictionary as per given input"""
        sniffer_dict = dict()
        frame_num = 0
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if packet_filter_frame in line:
                frame_num = line.split(':')[1].strip()
            if packet_filter_dtim0 in line:
                sniffer_dict[frame_num] = 'DTIM0'
            if packet_filter_ps_poll.strip() == line.strip():
                sniffer_dict[frame_num] = 'PS-Poll'
            if packet_filter_data.strip() == line.strip():
                sniffer_dict[frame_num] = 'Data'
        logger().info("---------Printing sniffer parse dictionary------------\n")
        filter_file.close()
        return sniffer_dict

    def validate_packet_for_max_psp(self, sniffer_dict):
        data_status = False
        ps_key = 0
        data_key = 0
        dtim0_key = 0

        """This function validates the packet sequence for DTIM count reaches 0(As per test case requirement need to validate
        Beacon(DTIM0)-> Ps-Poll-> Data packets sequentially"""

        for key, value in sniffer_dict.items():
            pass_status = []
            if value == 'DTIM0':
                dtim0_key = key
            if value == 'PS-Poll':
                if int(key) == int(dtim0_key) + 1:
                    ps_key = key
            if value == 'Data':
                if int(key) == int(ps_key) + 1:
                    data_key = key
                    data_status = True
            if data_status:
                logger().info(
                    f'\n Sequence of DUT wake time, Beacon = {dtim0_key}, PS-Poll = {ps_key}, Data = {data_key}\n ')
                data_status = False
                ps_poll_frame = ps_key
                data_frame = data_key

                logger().info(f'ps_poll_frame = {ps_poll_frame}, data_frame = {data_frame}')

                ps_poll_status = False
                data_status = False
                time_diff_list = []
                packet_filter1 = "Arrival Time:"
                frame_no = f'Frame {ps_key}:'
                data_frame_no = f'Frame {data_key}:'
                filter_file = open(f'./reports/filter2_file.txt', 'r')
                file_line_list = filter_file.readlines()

                for line in file_line_list:
                    if frame_no in line:
                        ps_poll_status = True
                        logger().info(f'PS -poll frame -->{frame_no}')
                        pass
                    if data_frame_no in line:
                        data_status = True
                        logger().info(f'Data frame no -->{data_frame_no}')
                        pass
                    if (packet_filter1 in line and ps_poll_status is True) or (
                            packet_filter1 in line and data_status is True):
                        result = re.search('2022(.*)IST', line)
                        time_stamp = result.group(1).strip()
                        logger().info(f'time_stamp={time_stamp}')
                        ps_poll_status = False
                        data_status = False
                        size = len(time_stamp)
                        mod_time_stamp = time_stamp[:size - 3]
                        time_diff_list.append(mod_time_stamp)

                logger().info(
                    f'PS-Poll data packet time = {time_diff_list[0]}, Qos Data packet time = {time_diff_list[1]}')

                time_diff_ps_poll_and_data_frame = datetime.datetime.strptime(time_diff_list[1],
                                                                              '%H:%M:%S.%f') - datetime.datetime.strptime(
                    time_diff_list[0], '%H:%M:%S.%f')
                logger().info(f"Time difference between ps-poll and Qos data frame: {time_diff_ps_poll_and_data_frame}")
                time_diff_in_ms = str(time_diff_ps_poll_and_data_frame)[7:14]
                logger().info(f'Time difference in ms = {time_diff_in_ms}')
                expected_time_between_ps_poll_and_data_frame = 0.021
                if float(time_diff_in_ms) <= expected_time_between_ps_poll_and_data_frame:
                    actual_time_diff = expected_time_between_ps_poll_and_data_frame - float(time_diff_in_ms)
                    logger().info(
                        f"Time difference between ps-poll = {time_diff_list[0]} & Qos data frame = {time_diff_list[1]} "
                        f"is less than 20ms")
                    logger().info("\n Actual time difference = %.4f" % actual_time_diff)
                    pass_status.append(True)
                else:
                    logger().info(
                        f"Time difference between ps-poll = {time_diff_list[0]} & Qos data frame = {time_diff_list[1]} "
                        f"is greater than 20ms")
                    pass_status.append(False)
        return False if False in pass_status else True

    def parse_sniffer_packet_max_psp_95_null_frame(self):
        packet_filter_frame = '    Frame Number:'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_null_data = '    Type/Subtype: QoS Null function (No data) (0x002c)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        packet_null = '    Type/Subtype: Null function (No data) (0x0024)'
        pmbit_0 = '            ...0 .... = PWR MGT: STA will stay up'
        pmbit_1 = '            ...1 .... = PWR MGT: STA will go to sleep'

        """This function takes the filter2_file.txt as a input and parse all captured sniffer packet and convert into
        dictionary as per given input for TC-19695"""
        """ Sequence will be PS-POLL - > Null frame + 0 -> Qos data -> Null frame + 1"""
        sniffer_dict = dict()
        frame_num = 0
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if packet_filter_frame in line:
                frame_num = line.split(':')[1].strip()
            if packet_filter_ps_poll.strip() == line.strip():
                sniffer_dict[frame_num] = 'PS-Poll'
            if packet_null.strip() == line.strip():
                sniffer_dict[frame_num] = 'NULL'
            if packet_filter_data.strip() == line.strip():
                sniffer_dict[frame_num] = 'Data'
            if packet_filter_null_data.strip() == line.strip():
                sniffer_dict[frame_num] = 'NULL_DATA'
            if pmbit_0.strip() == line.strip():
                sniffer_dict[frame_num + 'pm0'] = 'PM0'
            if pmbit_1.strip() == line.strip():
                sniffer_dict[frame_num + 'pm1'] = 'PM1'

        # logger().info("---------Printing sniffer parse dictionary------------\n")
        # logger().info(sniffer_dict)
        filter_file.close()
        return sniffer_dict

    def validate_packet_for_max_psp_null_frame(self, sniffer_dict, monitor_interval):
        pm1_status = False
        ps_key = 0
        data_key = 0
        null_key1 = 0
        null_key = 0
        pm0_status = False
        pass_status = []

        """This function validates the packet sequence for DTIM count reaches 0(As per test case requirement need to validate
        Beacon-> Ps-Poll-> Data packets sequentially"""

        for key, value in sniffer_dict.items():
            if value == 'PS-Poll':
                ps_key = key
            if value == 'NULL':
                if int(key) == int(ps_key) + 1:
                    null_key = key
            if value == 'PM0' and (key == str(null_key) + 'pm0'):
                pm0_status = True
            if ((value == 'Data') or (value == 'NULL_DATA')) and pm0_status is True:
                if int(key) == int(null_key) + 1:
                    data_key = key
            if value == 'NULL':
                if int(key) == int(data_key) + 1:
                    null_key1 = key
            if value == 'PM1' and (key == str(null_key1) + 'pm1'):
                pm1_status = True

            if pm1_status:
                logger().info(
                    'Validation for packet sequence PS-POLL -> Null frame + pm bit 0 -> Qos data -> Null frame + pm '
                    'bit 1')
                logger().info(f'\n PS-POLL = {ps_key}, NULL frame with pm bit 0 = {null_key}, Qos Data = {data_key},'
                              f' NULL frame with pm bit 1 = {null_key1}\n')
                pm1_status = False

                data_frame_status = False
                null_frame_status = False
                time_diff_list = []
                packet_filter1 = "Arrival Time:"
                data_frame_no = f'Frame {data_key}:'
                null_frame_no = f'Frame {null_key1}:'
                filter_file = open(f'./reports/filter2_file.txt', 'r')
                file_line_list = filter_file.readlines()

                for line in file_line_list:
                    if data_frame_no in line:
                        data_frame_status = True
                        print(f'Data frame no -->{data_frame_no}--->')
                        pass
                    if null_frame_no in line:
                        null_frame_status = True
                        print(f'NUll Frame no -->{null_frame_no}--->')
                        pass
                    if (packet_filter1 in line and data_frame_status is True) or (
                            packet_filter1 in line and null_frame_status is True):
                        result = re.search('2022(.*)IST', line)
                        time_stamp = result.group(1).strip()
                        print(f'time_stamp={time_stamp}')
                        data_frame_status = False
                        null_frame_status = False
                        size = len(time_stamp)
                        mod_time_stamp = time_stamp[:size - 3]
                        time_diff_list.append(mod_time_stamp)

                time_diff_ps_poll_and_data_frame = datetime.datetime.strptime(time_diff_list[1],
                                                                              '%H:%M:%S.%f') - datetime.datetime.strptime(
                    time_diff_list[0], '%H:%M:%S.%f')
                logger().info(f"Time difference between Qos data and NUll frame: {time_diff_ps_poll_and_data_frame}")
                time_diff_in_ms = str(time_diff_ps_poll_and_data_frame)[7:14]
                logger().info(f'Time difference in ms = {time_diff_in_ms}')
                expected_time_between_ps_poll_and_data_frame = monitor_interval / 1000
                if float(time_diff_in_ms) <= expected_time_between_ps_poll_and_data_frame:
                    logger().info(
                        f"\nTime difference between Qos data frame = {time_diff_list[0]} & NUll frame with pm bit 1 = "
                        f"{time_diff_list[1]} is less than {monitor_interval}ms \n")
                    pass_status.append(True)
                else:
                    logger().info(
                        f"Time difference between Qos data frame = {time_diff_list[0]} & NUll frame with pm bit 1 = "
                        f"{time_diff_list[1]} is greater than {monitor_interval}ms")
                    pass_status.append(False)
            else:
                '''************ No packet sequence found ************'''
                pass_status.append(False)
        # return False if False in pass_status else True
        if False in pass_status:
            logger().info(f'********* No packet sequence found ************')
            return False
        else:
            return True

    def connection_ble_spp_master_slave(self, wifi_dut, ble_client, dut_as_master=True, data_transfer=False):
        client_address = None
        if dut_as_master:
            logger().info(f'***** DUT BLE start as a master *****')
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None

            # Start ble client
            self.bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert self.bt_client_address is not None

            # Start scanning and connect to ble client
            wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.bt_client_address, timeout=15)

            timeout = 120
            wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=self.bt_client_address, timeout=timeout)

            client_address = self.bt_client_address

        elif dut_as_master is False:
            logger().info(f'***** DUT BLE start as a slave *****')
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            wifi_dut.interfaces.wifi.ble_start_advertising()

            # Begin Scanning for BLE devices
            time.sleep(3)
            self.bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert self.bt_client_address is not None
            time.sleep(3)
            ble_client.interfaces.bluetooth.stop_scanning()

            # See that we found our device
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            time.sleep(3)
            assert wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (
                    found_devices[wifi_dut.interfaces.wifi.ble_address]
                    == wifi_dut.interfaces.wifi.ble_advertising_data
            )
            ble_client.interfaces.bluetooth.connect(bt_dut_address)
            time.sleep(40)
            client_address = bt_dut_address

        # # Disconnect
        # wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.bt_client_address)
        logger().info(f"BT ADDRESS {client_address} ")
        return client_address

    def start_iperf_dut_as_server(self, wifi_dut, net_perf_client, protocol, device_ip, sl_collections):
        # # preparing iperf
        net_perf_client.interfaces.net_perf.init_client(
            device_ip=device_ip, protocol=protocol
        )

        # verifying host_ip
        wifi_dut.interfaces.wifi.ping(
            server_ip=str(net_perf_client.interfaces.net_perf.host_ip)
        )

        # creating results object for sharing between host and dut
        result = Result(net_perf_client.interfaces.net_perf.protocol)

        # open socket and start listening
        with sl_collections.start_socket_reader(
                log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
                result=result,
                protocol=net_perf_client.interfaces.net_perf.protocol,
                port=net_perf_client.interfaces.net_perf.client_port,
                device_ip=device_ip,
                data_len=net_perf_client.interfaces.net_perf.client_data_len,
                time=net_perf_client.interfaces.net_perf.client_timeout,
        ) as obj:
            # start iperf
            net_perf_client.interfaces.net_perf.start()
            # capture device output
            sl_collections.read_from_device(
                obj, net_perf_client.interfaces.net_perf.client_timeout
            )
        time.sleep(5)
        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None
        if tp is not None:
            print_dict("##     ", tp)

    def validate_time_delta(self, ps_poll_packets_time_delta_list, time_delta_for_listen_interval):
        list_status = []
        ps_poll_packets_time_delta_list.pop(0)
        del ps_poll_packets_time_delta_list[-1]
        logger().info(f'PS-poll packet time delta list after removing 0 = {ps_poll_packets_time_delta_list}')
        for time_diff in ps_poll_packets_time_delta_list:
            time_diff = int(round(time_diff, 3) * 1000)
            is_between = time_diff in range(time_delta_for_listen_interval, time_delta_for_listen_interval + 9)
            logger().info(f'is_between = {is_between}')
            if is_between is True:
                logger().info(
                    f'DUT sends PS-poll after 11 consecutive beacon frame and time diff is = {time_diff / 1000}')
                list_status.append(is_between)
            else:
                logger().info(
                    f'DUT unable to send PS-poll after 11 consecutive beacon frame and time diff is = {time_diff / 1000}')
                list_status.append(is_between)
        logger().info(list_status)
        return False if False in list_status else True

    def test_ble_multi_connect_disconnect(self, wifi_dut, ble_client):
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_start_advertising()

        # Begin Scanning for BLE devices
        self.bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert self.bt_client_address is not None
        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            if bt_dut_address in found_devices and \
                    found_devices[bt_dut_address] == wifi_dut.interfaces.wifi.ble_advertising_data:
                device_found = True
                break
        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found

        logger().info(f'\n ****** Connect *******\n')
        ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(2)
        logger().info(f'\n ****** Disonnect *******\n')
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)
        logger().info(f'\n ****** BLE start advertising *******\n')
        wifi_dut.interfaces.wifi.ble_start_advertising()
        time.sleep(1)
        logger().info(f'\n ****** Connect *******\n')
        ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(2)
        logger().info(f'\n ****** Disonnect *******\n')
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.PSKSecurity,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_wlan_ble_mode_c34469(wifi_sniffer, wifi_access_point, wifi_dut, net_perf_client, protocol,
                                       sniffer_filter, sl_collections):
    '''Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+BLE mode '''
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    # wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
    #                                               number_of_dtim_skip=0)
    #
    # wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # time.sleep(2)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34469')
    #
    # wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
    #                                  join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin,
    #                                  listen_interval=1100)
    #
    # dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    # logger().info(f"DUT MAC_Address: {dut_mac_address}")
    # wifi_dut.interfaces.wifi.start_ip()
    # device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    #
    # logger().info(f"*****Enable Max PSP in DUT******")
    # wifi_dut.interfaces.wifi.power_save(power_save_mode=Si91xPowerSaveModes.PowerSaveMode2,
    #                                     power_save_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
    # wifi_dut.interfaces.wifi.bt_power_save(
    #     power_save_mode=Si91xPowerSaveModes.PowerSaveMode2, power_save_type=Si91xPowerSaveProcedureTypes.FastPowerSave
    # )

    # ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    # filter_pack_obj.start_iperf_dut_as_server(wifi_dut, net_perf_client, protocol, device_ip,
    #                                           sl_collections=sl_collections)
    try:
        ''' Connect and Start Iperf traffic DUT as a server and Linux machine as a Client'''
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  net_perf_client=net_perf_client, protocol=protocol, sl_collections=sl_collections,
                                  test_case_name=34469)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], wlan_addr=ap_bssid,
             filter_name="coex_enhanced_max_psp_34469")

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA
        # ref.)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="beacon_assoc_id_ps_poll_with_pm_bit_enable")

        # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon
        # packets)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter. \
            get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="null_data_powersave")

        # packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
        #                  f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
        #                  f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
        # packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
        #                  f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

        # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
        # packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter2)[
            'packet_count']

        # Create ps poll packet time delta list
        ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)[
            'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_for_max_psp_95()
        result = filter_pack_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                            'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_more_data()
        assert filter_pack_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference---------------- ')
            sniffer_dict = filter_pack_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert filter_pack_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict, monitor_interval), 'No sequence found for sniffer packets ' \
                                                 'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info('***** Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & '
                          'Qos Data packet time difference passed successfully')
            assert True

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.OpenMode,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_coex_wlan_datatransfer_ble_master_c34474(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                           net_perf_client, protocol, sl_collections, sniffer_filter):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
      WLAN+DUAL mode and BLE is in connected state as master """
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()

    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    # wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
    #                                               number_of_dtim_skip=0)

    # wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # time.sleep(2)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34474')
    #
    # wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
    #                                  join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin,
    #                                  listen_interval=1100)
    #
    # dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    # logger().info(f"DUT MAC_Address: {dut_mac_address}")
    # ip_config = wifi_dut.interfaces.wifi.start_ip()
    # device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    # logger().info(f"*****Enable Max PSP in DUT******")
    # wifi_dut.interfaces.wifi.power_save(power_save_mode=Si91xPowerSaveModes.PowerSaveMode2,
    #                                     power_save_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
    # wifi_dut.interfaces.wifi.bt_power_save(
    #     power_save_mode=Si91xPowerSaveModes.PowerSaveMode2, power_save_type=Si91xPowerSaveProcedureTypes.FastPowerSave
    # )
    try:
        ''' Connect and Start Iperf traffic DUT as a server and Linux machine as a Client'''
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  net_perf_client=net_perf_client, protocol=protocol, sl_collections=sl_collections,
                                  test_case_name=34474)

        ''' Initiating BLE connection(Master) and should be in connected state'''
        ble_client_obj = BleThreadConnection(wifi_dut, ble_client)

        wlan_obj.start()
        ble_client_obj.start()
        wlan_obj.wait_for_exit()
        ble_client_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], wlan_addr=ap_bssid,
             filter_name="coex_enhanced_max_psp_34469")

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="beacon_assoc_id_ps_poll_with_pm_bit_enable")

        # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="null_data_powersave")

        # packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
        #                  f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
        #                  f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

        # # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
        # packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
        #                  f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'
        #
        # # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
        # packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

        time.sleep(20)
        ble_client_address = ble_client_obj.bt_client_address
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter2)[
            'packet_count']

        # Create ps poll packet time delta list
        ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)[
            'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_for_max_psp_95()
        result = filter_pack_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                            'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_more_data()
        assert filter_pack_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference---------------- ')
            sniffer_dict = filter_pack_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert filter_pack_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict, monitor_interval), 'No sequence found for sniffer packets ' \
                                                 'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info('***** Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & '
                          'Qos Data packet time difference passed successfully')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
# @pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.OpenMode,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        # "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        # "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.
        #     Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_coex_wlan_datatransfer_ble_slave_c34475(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                          net_perf_client, protocol, sl_collections, sniffer_filter):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode and BLE is in connected state as slave"""
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    # wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
    #                                               number_of_dtim_skip=0)
    #
    # wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # time.sleep(2)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34475')
    #
    # wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
    #                                  join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin,
    #                                  listen_interval=1100)
    #
    # dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    # logger().info(f"DUT MAC_Address: {dut_mac_address}")
    # ip_config = wifi_dut.interfaces.wifi.start_ip()
    # device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    #
    # logger().info(f"*****Enable Max PSP in DUT******")
    # wifi_dut.interfaces.wifi.power_save(power_save_mode=Si91xPowerSaveModes.PowerSaveMode2,
    #                                     power_save_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
    # wifi_dut.interfaces.wifi.bt_power_save(
    #     power_save_mode=Si91xPowerSaveModes.PowerSaveMode2, power_save_type=Si91xPowerSaveProcedureTypes.MaxPowerSave
    # )
    try:
        ''' Connect and Start Iperf traffic DUT as a server and Linux machine as a Client'''
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  net_perf_client=net_perf_client, protocol=protocol, sl_collections=sl_collections,
                                  test_case_name=34475)

        ''' Initiating BLE connection(Slave) and should be in connected state'''
        ble_client_obj = BleThreadConnection(wifi_dut, ble_client, mode=False)

        wlan_obj.start()
        ble_client_obj.start()
        wlan_obj.wait_for_exit()
        ble_client_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], wlan_addr=ap_bssid,
             filter_name="coex_enhanced_max_psp_34469")

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA
        # ref.)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="beacon_assoc_id_ps_poll_with_pm_bit_enable")

        # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon
        # packets)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="null_data_powersave")

        # packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
        #                  f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
        #                  f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
        # packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
        #                  f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'
        #
        # # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
        # packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_obj.ble_cli_add)

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter2)[
            'packet_count']

        # Create ps poll packet time delta list
        ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)[
            'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_for_max_psp_95()
        result = filter_pack_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                            'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_more_data()
        assert filter_pack_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference---------------- ')
            sniffer_dict = filter_pack_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert filter_pack_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict, monitor_interval), 'No sequence found for sniffer packets ' \
                                                 'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info('***** Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & '
                          'Qos Data packet time difference passed successfully')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.OpenMode,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_coex_ble_wlan_datatransfer_c34476(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                    net_perf_client, protocol, sl_collections, sniffer_filter):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode with BLE and WLAN data transfer"""
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    # wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
    #                                               number_of_dtim_skip=0)
    #
    # wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # time.sleep(2)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34471')
    #
    # wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
    #                                  join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin,
    #                                  listen_interval=1100)
    #
    # dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    # logger().info(f"DUT MAC_Address: {dut_mac_address}")
    # ip_config = wifi_dut.interfaces.wifi.start_ip()
    # device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    #
    # logger().info(f"*****Enable Max PSP in DUT******")
    # wifi_dut.interfaces.wifi.power_save(power_save_mode=Si91xPowerSaveModes.PowerSaveMode2,
    #                                     power_save_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
    # wifi_dut.interfaces.wifi.bt_power_save(
    #     power_save_mode=Si91xPowerSaveModes.PowerSaveMode2, power_save_type=Si91xPowerSaveProcedureTypes.FastPowerSave
    # )
    try:
        ''' Connect & Start Iperf traffic DUT as a server and Linux machine as a Client'''
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  net_perf_client=net_perf_client, protocol=protocol, sl_collections=sl_collections,
                                  test_case_name=34476)

        ''' Initiating BLE connection(Master) and start data transfer '''
        ble_obj = BleThreadConnectionDataTransfer(wifi_dut, ble_client)

        ble_obj.start()
        wlan_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], wlan_addr=ap_bssid,
             filter_name="coex_enhanced_max_psp_34469")

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="beacon_assoc_id_ps_poll_with_pm_bit_enable")

        # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="null_data_powersave")
        # packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
        #                  f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
        #                  f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'
        #
        # # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
        # packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
        #                  f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'
        #
        # # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
        # packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter2)[
            'packet_count']

        # Create ps poll packet time delta list
        ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)[
            'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_for_max_psp_95()
        result = filter_pack_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                            'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_more_data()
        assert filter_pack_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference---------------- ')
            sniffer_dict = filter_pack_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert filter_pack_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict, monitor_interval), 'No sequence found for sniffer packets ' \
                                                 'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info('***** Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & '
                          'Qos Data packet time difference passed successfully')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.OpenMode,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_ble_connect_disconnect_wlan_datatransfer_c34477(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                                  net_perf_client, protocol, sl_collections,
                                                                  sniffer_filter):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode with while doing BLE connect and disconnect """
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    # '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    # wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
    #                                               number_of_dtim_skip=0)
    #
    # wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # time.sleep(2)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34477')
    #
    # wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
    #                                  join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin,
    #                                  listen_interval=1100)
    #
    # dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    # logger().info(f"DUT MAC_Address: {dut_mac_address}")
    # ip_config = wifi_dut.interfaces.wifi.start_ip()
    # device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    #
    # logger().info(f"*****Enable Max PSP in DUT******")
    # wifi_dut.interfaces.wifi.power_save(power_save_mode=Si91xPowerSaveModes.PowerSaveMode2,
    #                                     power_save_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
    # wifi_dut.interfaces.wifi.bt_power_save(
    #     power_save_mode=Si91xPowerSaveModes.PowerSaveMode2, power_save_type=Si91xPowerSaveProcedureTypes.FastPowerSave
    # )
    try:
        ''' Connect and Start Iperf traffic DUT as a server and Linux machine as a Client'''
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  net_perf_client=net_perf_client, protocol=protocol, sl_collections=sl_collections,
                                  test_case_name=34477)
        ''' Initiating BLE connection(Master) and should be in connected state'''
        ble_client_obj = BleThreadConnectionDisconnection(wifi_dut, ble_client)

        wlan_obj.start()
        ble_client_obj.start()
        wlan_obj.wait_for_exit()
        ble_client_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], wlan_addr=ap_bssid,
             filter_name="coex_enhanced_max_psp_34469")

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="beacon_assoc_id_ps_poll_with_pm_bit_enable")

        # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="null_data_powersave")

        # packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
        #                  f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
        #                  f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'
        #
        # # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
        # packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
        #                  f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'
        #
        # # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
        # packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter2)[
            'packet_count']

        # Create ps poll packet time delta list
        ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)[
            'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_for_max_psp_95()
        result = filter_pack_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                            'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_more_data()
        assert filter_pack_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference---------------- ')
            sniffer_dict = filter_pack_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert filter_pack_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict, monitor_interval), 'No sequence found for sniffer packets ' \
                                                 'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info('***** Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & '
                          'Qos Data packet time difference passed successfully')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.OpenMode,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_coex_wlan_datatransfer_ble_connect_disconnect_c34478(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                       ble_client, net_perf_client, protocol,
                                                                       sl_collections, sniffer_filter):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode with while doing BLE connect and disconnect with DTIM based and monitor interval 70 """
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 70

    # '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    # wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
    #                                               number_of_dtim_skip=0)
    #
    # wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # time.sleep(2)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34478')
    #
    # wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
    #                                  join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin,
    #                                  listen_interval=1100)
    #
    # dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    # logger().info(f"DUT MAC_Address: {dut_mac_address}")
    # ip_config = wifi_dut.interfaces.wifi.start_ip()
    # device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    #
    # logger().info(f"*****Enable Max PSP in DUT******")
    # wifi_dut.interfaces.wifi.power_save(power_save_mode=Si91xPowerSaveModes.PowerSaveMode2,
    #                                     power_save_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
    # wifi_dut.interfaces.wifi.bt_power_save(
    #     power_save_mode=Si91xPowerSaveModes.PowerSaveMode2, power_save_type=Si91xPowerSaveProcedureTypes.FastPowerSave
    # )

    try:
        ''' Connect and Start Iperf traffic DUT as a server and Linux machine as a Client'''
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  net_perf_client=net_perf_client, protocol=protocol, sl_collections=sl_collections,
                                  test_case_name=34478)
        ''' Initiating BLE connection and should be in connected state'''
        ble_client_obj = BleThreadConnectionDisconnection(wifi_dut, ble_client)

        wlan_obj.start()
        ble_client_obj.start()
        wlan_obj.wait_for_exit()
        ble_client_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], wlan_addr=ap_bssid,
             filter_name="coex_enhanced_max_psp_34469")

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="beacon_assoc_id_ps_poll_with_pm_bit_enable")

        # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="null_data_powersave")

        # packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
        #                  f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
        #                  f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'
        #
        # # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
        # packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
        #                  f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'
        #
        # # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
        # packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter2)[
            'packet_count']

        # Create ps poll packet time delta list
        ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)[
            'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_for_max_psp_95()
        result = filter_pack_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                            'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_more_data()
        assert filter_pack_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference---------------- ')
            sniffer_dict = filter_pack_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert filter_pack_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict, monitor_interval), 'No sequence found for sniffer packets ' \
                                                 'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info('***** Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & '
                          'Qos Data packet time difference passed successfully')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.OpenMode,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_coex_ble_wlan_datatransfer_dtim_based_c34479(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                               net_perf_client, protocol, sl_collections,
                                                               sniffer_filter):
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    ps_packet_exchange_obj = FilterPacket()
    '''Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in 
    WLAN+DUAL mode with BLE and WLAN data transfer in DTIM based'''

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_maxpsp_C34479')
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.start_ap()

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    # wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # time.sleep(2)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34479')
    #
    # wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=Si91xJoinFeatureBitMap.Default)
    #
    # dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    # logger().info(f"DUT MAC_Address: {dut_mac_address}")
    #
    # ip_config = wifi_dut.interfaces.wifi.start_ip()
    # device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    #
    # logger().info(f"*****Enable Max PSP in DUT******")
    # wifi_dut.interfaces.wifi.power_save(power_save_mode=Si91xPowerSaveModes.PowerSaveMode2,
    #                                     power_save_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
    # wifi_dut.interfaces.wifi.bt_power_save(
    #     power_save_mode=Si91xPowerSaveModes.PowerSaveMode2, power_save_type=Si91xPowerSaveProcedureTypes.MaxPowerSave
    # )

    try:
        ''' Connect and Start Iperf traffic DUT as a server and Linux machine as a Client'''
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  net_perf_client=net_perf_client, protocol=protocol, sl_collections=sl_collections,
                                  test_case_name=34478)
        ''' Initiating BLE connection and should be able to connect & data transfer'''
        ble_client_obj = BleThreadConnectionDataTransfer(wifi_dut, ble_client)

        wlan_obj.start()
        ble_client_obj.start()
        ble_client_obj.wait_for_exit()
        wlan_obj.wait_for_exit()

        # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'], da_addr=ap_bssid,
             filter_name="beacon_assoc_id_dtim_count_ps_poll_with_pm_bit_enable")

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable -> Qos
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (filter_name="beacon_assoc_id_ps_poll_with_pm_bit_enable_qos")

        # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
        # packet_filter3 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a) || ' \
        #                  f'(wlan.addr == {ap_bssid} && ' \
        #                  f'(wlan.fc.type_subtype ==8) || (wlan.fc.type_subtype==0x0028) || (wlan.fc.type_subtype==0x002c))'

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable -> Qos
        # packet_filter4 = f'(wlan.fc.type_subtype == 0x001a || wlan.fc.type_subtype == 0x0028) || (wlan.tim.dtim_count == 0 ' \
        #                  f'&& wlan.tim.dtim_period == 3 && wlan.tim.aid == 0x01)'

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count']

        # Validate beacon DTIM count=0
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter2)[
            'packet_count']

        # Create ps poll packet time delta list
        ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

        logger().info('-----------Validation for DTIM count = 0 sequence---------------- ')
        sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packets()
        assert ps_packet_exchange_obj.match_packet_sequence(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                           'Beacon(DTIM count=0)-> Ps-Poll-> Data'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packet_more_data()
        assert ps_packet_exchange_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.OpenMode,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_ble_connect_disconnect_wlan_datatransfer_c34488(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                                  net_perf_client, protocol, sl_collections,
                                                                  sniffer_filter):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
        WLAN+DUAL mode while doing WLAN data transfer do continuous BLE connect and disconnect"""
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 10
    ''' Note this test cases has one failure 0x4b0b(SMP DH Key check failed)
        https://docs.silabs.com/Si91x-wiseconnect/latest/wifibt-wc-sapi-reference/error-codes'''

    # '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    # wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
    #                                               number_of_dtim_skip=0)
    #
    # wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # time.sleep(2)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34488')
    #
    # wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
    #                                  join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin,
    #                                  listen_interval=1100)
    #
    # dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    # logger().info(f"DUT MAC_Address: {dut_mac_address}")
    # ip_config = wifi_dut.interfaces.wifi.start_ip()
    # device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    #
    # logger().info(f"*****Enable Max PSP in DUT******")
    # wifi_dut.interfaces.wifi.power_save(power_save_mode=Si91xPowerSaveModes.PowerSaveMode2,
    #                                     power_save_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
    # wifi_dut.interfaces.wifi.bt_power_save(
    #     power_save_mode=Si91xPowerSaveModes.PowerSaveMode2, power_save_type=Si91xPowerSaveProcedureTypes.FastPowerSave
    # )

    try:
        ''' Connect and Start Iperf traffic DUT as a server and Linux machine as a Client'''
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  net_perf_client=net_perf_client, protocol=protocol, sl_collections=sl_collections,
                                  test_case_name=34488)
        ''' Initiating BT connection and should be in connected state '''
        ble_client_obj = BleThreadConnectionDisconnection(wifi_dut, ble_client)

        ble_client_obj.start()
        ble_client_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], wlan_addr=ap_bssid,
             filter_name="coex_enhanced_max_psp_34469")

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (da_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="beacon_assoc_id_ps_poll_with_pm_bit_enable")

        # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="null_data_powersave")

        # packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
        #                  f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
        #                  f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'
        #
        # # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
        # packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
        #                  f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'
        #
        # # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
        # packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter2)[
            'packet_count']

        # Create ps poll packet time delta list
        ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)[
            'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_for_max_psp_95()
        result = filter_pack_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                            'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = filter_pack_obj.parse_sniffer_packet_more_data()
        assert filter_pack_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference---------------- ')
            sniffer_dict = filter_pack_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert filter_pack_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict, monitor_interval), 'No sequence found for sniffer packets ' \
                                                 'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info('***** Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & '
                          'Qos Data packet time difference passed successfully')
            assert True

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
