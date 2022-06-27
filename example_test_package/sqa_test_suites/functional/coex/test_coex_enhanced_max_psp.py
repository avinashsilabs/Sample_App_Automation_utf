import re
import time
from datetime import datetime, timedelta
import datetime
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.bluetooth import BTSocketRole
from utf.interfaces.wifi import WlanError
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, ping
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from numpy import arange
import pytest as pytest
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116DataRate, RS9116RejoinParams, RS9116JoinFeatureBitMap, \
    RS9116PowerSaveProcedureTypes, RS9116ExtCustomFeatureBitMap, RS9116BTFeatureBitMap
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,

)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


class TcpIpSockets:
    def open_socket(self, wifi_dut, dut_ip) -> int:
        tcp_socket_id = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        if isinstance(tcp_socket_id, int):
            logger().info(f"Socket open successfully : {tcp_socket_id}")
        else:
            logger().error(f"Unable to open socket id: {tcp_socket_id}")
            raise RuntimeError(tcp_socket_id)

        time.sleep(2)
        bind_response = wifi_dut.interfaces.wifi.bind(tcp_socket_id, dut_ip)
        if bind_response.decode().split(">")[1].replace("'", '').strip() == 'success':
            logger().info(f"Bind socket successfully: {bind_response}")
        else:
            logger().error(f"Unable to bind socket: {bind_response}")
            raise RuntimeError(bind_response)
        return tcp_socket_id

    def connect_socket(self, wifi_dut, tcp_socket_id: int, server_ip, server_port):
        retry_limit: int = 2
        connect_status = False
        for retry in range(1, retry_limit):
            connect_response = wifi_dut.interfaces.wifi.connect(tcp_socket_id, server_ip, server_port)
            logger().info(f"Connect response : {connect_response}")
            if connect_response.decode() == '':
                logger().info(f"Unable to connect socket: {connect_response} in {retry} try")
                if retry < retry_limit:
                    pass
            elif connect_response.decode().split(">")[1].strip() == 'success':
                logger().info(f"Socket connected successfully in {retry} try")
                connect_status = True
                break
            logger().info(f"Socket connected with server in: {retry + 1} time")
        return connect_status


class BtThreadDisconnection(ThreadBase):
    def __init__(self, wifi_dut, bt_cli_add):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client_address = bt_cli_add

    def run(self):
      self.wifi_dut.interfaces.wifi.bt_disconnect(self.bt_client_address)


class BtSppScan(ThreadBase):
    def __init__(self, wifi_dut, bt_client, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.bt_client = bt_client

    def run(self):
        self.logger.info('this is bt run')
        # BT as Master and connect to remote BT[raspi] & validation for connect and disconnect multiple times
        for i in range(0, 10):
            inq_type = 2
            duration = 10000
            max_no_dev = 10
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None
            # time.sleep(2)
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None
            # time.sleep(0.5)

            # # Added set class to 400100 to avoid [Errno 112] Host is down issue
            # self.bt_client.interfaces.bluetooth.bt_adapter.set_class('400100')

            with self.bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Client
            ) as bt_client_socket:
                # SPP Enquiry
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_client_socket.create_client()
                    self.wifi_dut.interfaces.wifi.bt_inquiry(inq_type, duration, max_no_dev)
                    time.sleep(duration/1000)
                    # Get Asynchronous messages
                    events = self.wifi_dut.interfaces.wifi.get_async_events()
                    assert len(events) > 0
                    # Search for Inquiry type and Remote BT device address
                    for event in events:
                        event_data = str(event.event_data.decode())
                    if bt_client_address in event_data and 'Inquiry_type = 0' in event_data:
                        logger().info(f'Inquiry type is = {inq_type}')
                    logger().info(f'BT address found = {bt_client_address}')


class BtSppThreadConnectionDataTransfer(ThreadBase):
    def __init__(self, wifi_dut, bt_client, dut_as_master=True, data_transfer=False):
        super().__init__()
        self.connect_data_trans_obj = FilterPacket()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.data_transfer = data_transfer
        self.dut_as_master = dut_as_master
        self.bt_client_address = None

    def run(self):
        self.bt_client_address = self.connect_data_trans_obj.connection_bt_spp_master_slave(self.wifi_dut, self.bt_client, self.dut_as_master,
                                                                   self.data_transfer)
        # logger().info(f'BT client address = {bt_client_address}')

class BtSppThreadA2DP(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.bt_A2dp_obj = FilterPacket()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        self.bt_A2dp_obj.test_bt_a2dp_simple_play(self.wifi_dut, self.bt_client)


class BleThreadDisconnection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, ble_cli_add):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.bt_client_address = ble_cli_add

    def run(self):
        time.sleep(10)
        self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.bt_client_address, timeout=30)


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
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=self.bt_dut_address)
            self.ble_cli_add = self.bt_client_address
            assert self.bt_client_address is not None

            # Start scanning and connect to ble client
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.bt_client_address, timeout=15)
            time.sleep(10)

        elif self.mode is False:
            self.logger.info('***** DUT BLE as a Slave *****')
            # Set up DUT for BLE advertising
            self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert self.bt_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            # Begin Scanning for BLE devices
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.bt_dut_address)
            assert bt_client_address is not None
            time.sleep(3)
            self.ble_client.interfaces.bluetooth.stop_scanning()

            # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            self.ble_cli_add = bt_client_address
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (
                    found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                    == self.wifi_dut.interfaces.wifi.ble_advertising_data
            )

    def run(self):
        if self.mode:
            self.logger.info('***** DUT BLE as a Master *****')
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=self.bt_client_address, timeout=30)

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
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None

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
        bus = self.ble_client.interfaces.bluetooth.bus
        servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(
            bus)
        assert len(servs) > 0
        assert len(chars) > 0

        char, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                                    services=servs,
                                                                                                    service_uid=service_uid,
                                                                                                    char_uid=char_uid)
        assert char is not None
        assert len(char_props) > 0

        # read value - Notifications not enabled
        result = self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data1

        # subscribe to notifications
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                     char_uid=char_uid)

        # notify only
        self.wifi_dut.interfaces.wifi.ble_notify_value()

        # write/read new value - Notifications enabled
        self.ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data2)
        time.sleep(0.1)
        result = self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data2

        # write value - Notifications enabled
        self.ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data3)

        # auto notify
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                     char_uid=char_uid)
        self.wifi_dut.interfaces.wifi.ble_start_notify_value(interval_ms=500, count=2)
        time.sleep(1)

        # subscribe to notifications
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(characteristic=char)
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
    def __init__(self, wifi_dut, net_perf_client, protocol, device_ip):
        super().__init__()
        self.iperf_obj = FilterPacket()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.device_ip = device_ip

    def run(self):
        self.iperf_obj.start_iperf_dut_as_server(self.wifi_dut, self.net_perf_client, self.protocol, self.device_ip)


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

    def parse_sniffer_packet_dtim_beacon(self):
        packet_filter_frame = '    Frame Number:'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        packet_filter_dtim0 = '            DTIM count: 0'
        packet_filter_dtim1 = '            DTIM count: 1'
        packet_assoc_id = '            Association ID: 0x01'
        sniffer_dict = dict()
        frame_num = 0
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if packet_filter_frame in line:
                frame_num = line.split(':')[1].strip()
            if packet_filter_dtim1 in line:
                sniffer_dict[frame_num] = 'DTIM1'
            if packet_filter_dtim0 in line:
                sniffer_dict[frame_num] = 'DTIM0'
            if packet_assoc_id in line:
                sniffer_dict[frame_num + 'A'] = 'DTIM_Beacon'
            if packet_filter_ps_poll in line:
                sniffer_dict[frame_num] = 'PS-Poll'
            if packet_filter_data in line:
                sniffer_dict[frame_num] = 'Qos Data'

        filter_file.close()
        logger().info("---------Printing sniffer parse dictionary------------\n")
        logger().info(sniffer_dict)
        return sniffer_dict

    def validate_packet_for_dtim_beacon(self, sniffer_dict):
        dtim1_status = False
        dtim0_status = False
        dtim_beacon_status = False
        ps_poll_status = False
        data_status = False
        status = False
        data_key = 0
        ps_poll_key = 0
        dtim1_key = 0
        dtim0_key = 0
        counter = 0
        match_key = 0

        for key, value in sniffer_dict.items():
            if value == 'DTIM1' or ((value == 'DTIM1') and (int(key) == int(dtim0_key) + 1)):
                dtim1_key = key
                dtim1_status = True
            if value == 'DTIM0':
                if (int(key) == int(dtim1_key) + 1) and (dtim1_status is True):
                    dtim0_key = key
                    dtim0_status = True
                    if counter < 5:
                        counter = counter + 1

            if (value == 'DTIM_Beacon') and (key == dtim0_key + 'A') and (counter == 5):
                dtim_beacon_key = key
                dtim_beacon_status = True
                match_key = dtim_beacon_key.split('A')[0]

            if value == 'PS-Poll':
                if int(key) == int(match_key) + 1:
                    ps_poll_key = key
                    ps_poll_status = True
                else:
                    pass

            if value == 'Qos Data':
                if int(key) == int(ps_poll_key) + 1:
                    data_key = key
                    data_status = True

            if dtim0_status:
                logger().info(f'Beacon+DTIM1 = {dtim1_key}, Beacon+DTIM0 = {dtim0_key}')
                dtim1_status = False
                dtim0_status = False
                # if counter < 5:
                #     logger().info(f'Beacon+DTIM1 = {dtim1_key}, Beacon+DTIM0 = {dtim0_key}')
                #     dtim1_status = False
                #     dtim0_status = False
                # else:
                #     pass

            if (dtim_beacon_status == True) and (ps_poll_status == True) and (data_status == True):
                logger().info(f'DTIM Beacon = {dtim_beacon_key}, PS-Poll = {ps_poll_key}, Qos Data = {data_key}\n\n')
                dtim_beacon_status = False
                ps_poll_status = False
                data_status = False
                counter = 0
                status = True
        if status:
            logger().info("------------------Expected packet sequence found--------------")
            return status
        else:
            logger().info("------------------Expected packet sequence not found--------------")
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

        """This function validates the packet sequence for DTIM count reaches 0(As per test case requirement need to validate
        Beacon-> Ps-Poll-> Data packets sequentially"""

        for key, value in sniffer_dict.items():
            pass_status = []
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
                    'Validation for packet sequence PS-POLL -> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1')
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

    def connection_bt_spp_master_slave(self, wifi_dut, bt_client, dut_as_master=True,
                                       data_transfer=False):
        with TimeMeasurer() as t:
            if dut_as_master:
                bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
                assert bt_dut_address is not None

                bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
                assert bt_client_address is not None
                time.sleep(0.5)

                # Added set class to 400100 to avoid [Errno 112] Host is down issue
                bt_client.interfaces.bluetooth.bt_adapter.set_class('400100')

                with bt_client.interfaces.bluetooth.bt_socket(
                        mode=BTSocketRole.Client
                ) as bt_client_socket:
                    # SPP Connection
                    with wifi_dut.interfaces.wifi.run_bt_task():
                        bt_client_socket.create_client()
                        result = ThreadBase.call_functions_simultaneously(
                            [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address), (bt_client_socket.accept, 20)])
                        assert result[1] == bt_dut_address
                        logger().info(f"Result from Callable Function {result}")
                    # Ping dut
                    assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                        dest_addr=bt_dut_address
                    )

                    # Check for data transfer
                    if data_transfer:
                        send_text = "sA0L9b1xEgGuUqN5YOlx" * 10
                        recv_text = "H2D7yZKRhKULU9Xil5Yv" * 10
                        # Send data from bt_client to dut
                        with wifi_dut.interfaces.wifi.run_bt_task():
                            sent = bt_client_socket.send(
                                recv_text
                            )  # Dut is programmed to send back data
                            assert sent
                            data = bt_client_socket.recv()
                            assert data is not None
                            assert data.decode() == recv_text

                        # Send data from dut to bt_client
                        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                        data = bt_client_socket.recv()
                        assert data is not None
                        assert data.decode() == send_text

                    # Ping dut
                    assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                        dest_addr=bt_dut_address
                    )

                    # Close connection
                    bt_client_socket.close()
                    time.sleep(
                        0.2
                    )
            elif dut_as_master is False:
                bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
                assert bt_dut_address is not None

                bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
                assert bt_client_address is not None

                # Added set class to 400100 to avoid [Errno 112] Host is down issue
                bt_client.interfaces.bluetooth.bt_adapter.set_class('400100')

                with bt_client.interfaces.bluetooth.bt_socket(
                        mode=BTSocketRole.Server
                ) as bt_server_socket:
                    # SPP Connection
                    with wifi_dut.interfaces.wifi.run_bt_task():
                        bt_server_socket.create_server()
                        connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                        assert connected

                    if data_transfer:
                        send_text = "sA0L9b1xEgGuUqN5YOlx" * 10
                        recv_text = "H2D7yZKRhKULU9Xil5Yv" * 10
                        # Send data from bt_client to dut
                        with wifi_dut.interfaces.wifi.run_bt_task():
                            sent = bt_server_socket.send(
                                recv_text
                            )  # SQA Agent is programmed to send back data
                            assert sent
                            data = bt_server_socket.recv()
                            assert data is not None
                            assert data.decode() == recv_text

                        # Send data from dut to bt_client
                        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                        data = bt_server_socket.recv()
                        assert data is not None
                        assert data.decode() == send_text

                    # Ping dut
                    assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                        dest_addr=bt_dut_address
                    )

                    # Close connection
                    bt_server_socket.close()

        logger().info(f"Scan in {t.duration} seconds")
        logger().info(f"BT ADDRESS {bt_client_address} ")
        return bt_client_address

    def test_bt_a2dp_simple_play(self, wifi_dut, bt_client):
        inq_type = 1
        duration = 10000
        max_no_dev = 10
        event_data = ""
        capture_file_path = "./reports/a2dp_capture_test_bt_a2dp_dut_simple_play_C20054.wav"
        with TimeMeasurer() as t:
            logger().info("========Configure DUT in a2dp Initiator_Role===============")
            bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_a2dp()
            assert bt_dut_address is not None
            logger().info("===========Configure Raspberry pi device as sink===========")
            bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink(bt_dut_address=bt_dut_address,
                                                                               pin_code=pin_code)
            assert bt_client_address is not None
            logger().info(f'Start BT inquiry with RSSI from DUT')
            wifi_dut.interfaces.wifi.bt_inquiry(inq_type, duration, max_no_dev)
            time.sleep(duration / 1000)
            # Get Asynchronous messages
            events = wifi_dut.interfaces.wifi.get_async_events()
            assert len(events) > 0
            # Search for Inquiry type and Remote BT device address
            for event in events:
                event_data = event_data + str(event.event_data.decode())
                if bt_client_address in event_data:
                    logger().info(f'Remote BT address found ==> {bt_client_address}')
                    break
            logger().info("=========Initiating BT Connection and followed by A2DP Connection=========")
            wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
            time.sleep(10)
            # Ping dut
            logger().info("=========Invoke the L2ping===========")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )
            # Start capturing audio
            logger().info("==============Start Capturing audio================")
            bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
            # A2DP SBC Audio streaming to Raspi
            logger().info("==============Start A2DP SBC Audio streaming from DUT to Raspberry===========")
            wifi_dut.interfaces.wifi.bt_a2dp_start_sbc_streaming()
            time.sleep(3)
            # assert the captured audio size
            logger().info("============Capturing the size of audio file=============")
            captured_audio_size = bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
            logger().info(f"captured_audio_size : {captured_audio_size}")
            # So here we are getting the captured audio size in bytes that is divided into 1 lakh to get in MB
            # here we are checking the size in between 5 to 6 MB , 5 is Minimum and 6 is Maximum
            assert 5 <= int(captured_audio_size / 100000) <= 6
        logger().info(f"Test case executed in {t.duration} seconds")

    def connection_ble_spp_master_slave(self, wifi_dut, ble_client, dut_as_master=True, data_transfer=False):
        if dut_as_master:
            logger().info(f'***** DUT BLE start as a master *****')
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None

            # Start ble client
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None

            # Start scanning and connect to ble client
            wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=15)

            timeout = 120
            wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

            client_address = bt_client_address

        elif dut_as_master is False:
            logger().info(f'***** DUT BLE start as a slave *****')
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            wifi_dut.interfaces.wifi.ble_start_advertising()

            # Begin Scanning for BLE devices
            time.sleep(3)
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
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
        # wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(f"BT ADDRESS {client_address} ")
        return client_address

    def start_iperf_dut_as_server(self, wifi_dut, net_perf_client, protocol, device_ip):
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
        with wifi_dut.interfaces.wifi.start_socket_reader(
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
            wifi_dut.interfaces.wifi.read_from_device(
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
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None
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
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_wlan_dual_mode_c34467(wifi_sniffer, wifi_access_point, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34467')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Power save mode in DUT******")

    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.MaxPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.MaxPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    filter_pack_obj.start_iperf_dut_as_server(wifi_dut, net_perf_client, protocol, device_ip)

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'
    ''' '''
    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
    },
)
def test_wlan_bt_mode_c34468(wifi_sniffer, wifi_access_point, wifi_dut, net_perf_client, protocol):
    '''Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+BT mode '''
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34468')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    filter_pack_obj.start_iperf_dut_as_server(wifi_dut, net_perf_client, protocol, device_ip)

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'
    ''' '''
    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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
            sniffer_dict), 'No sequence found for sniffer packets ' \
                           'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
    else:
        logger().info('***** Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & '
                      'Qos Data packet time difference passed successfully')
        assert True


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
    },
)
def test_wlan_ble_mode_c34469(wifi_sniffer, wifi_access_point, wifi_dut, net_perf_client, protocol):
    '''Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+BLE mode '''
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34469')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    filter_pack_obj.start_iperf_dut_as_server(wifi_dut, net_perf_client, protocol, device_ip)

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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
            sniffer_dict), 'No sequence found for sniffer packets ' \
                           'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
    else:
        logger().info('***** Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & '
                      'Qos Data packet time difference passed successfully')
        assert True


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_coex_bt_master_wlan_dual_mode_c34470(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode and BT is in connected state as a master """
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34470')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)

    ''' Initiating BT connection and should be in connected state'''
    bt_client_obj = BtSppThreadConnectionDataTransfer(wifi_dut, bt_client, dut_as_master=True, data_transfer=False)

    wlan_obj.start()
    bt_client_obj.start()
    wlan_obj.wait_for_exit()
    bt_client_obj.wait_for_exit()


    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(20)
    bt_client_address = bt_client_obj.bt_client_address
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_coex_bt_wlan_data_transfer_c34471(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode with BT and WLAN data transfer """
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34471')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)

    ''' Initiating BT connection, DUT as a Master & send/receive data '''
    bt_client_obj = BtSppThreadConnectionDataTransfer(wifi_dut, bt_client, dut_as_master=True, data_transfer=True)

    wlan_obj.start()
    bt_client_obj.start()
    wlan_obj.wait_for_exit()
    bt_client_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(20)
    bt_client_address = bt_client_obj.bt_client_address
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_coex_bt_slave_wlan_data_transfer_c34472(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
     WLAN+DUAL mode and BT is in connected state as a slave """
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in 
       WLAN+DUAL mode and BT is in connected state as a slave '''
    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34472')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)

    ''' Initiating BT connection and should be in connected state'''
    bt_client_obj = BtSppThreadConnectionDataTransfer(wifi_dut, bt_client, dut_as_master=False, data_transfer=False)

    wlan_obj.start()
    bt_client_obj.start()
    wlan_obj.wait_for_exit()
    bt_client_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(20)
    bt_client_address = bt_client_obj.bt_client_address
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_coex_wlan_data_transfer_bt_connect_disconnect_c34473(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode with while doing WLAN data transfer do BT connect and disconnect
    """
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34473')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)

    ''' Initiating BT connection and should be in connected state'''
    bt_client_obj = BtSppThreadConnectionDataTransfer(wifi_dut, bt_client, dut_as_master=True, data_transfer=False)

    wlan_obj.start()
    bt_client_obj.start()

    logger().info(f'BT client address = {bt_client_obj.bt_client_address}')
    time.sleep(15)
    bt_disconnection_obj = BtThreadDisconnection(wifi_dut, bt_client_obj.bt_client_address)
    bt_disconnection_obj.start()
    wlan_obj.wait_for_exit()
    bt_client_obj.wait_for_exit()
    bt_disconnection_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(20)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_coex_wlan_datatransfer_ble_master_c34474(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
      WLAN+DUAL mode and BLE is in connected state as master """
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34474')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)

    ''' Initiating BLE connection(Master) and should be in connected state'''
    ble_client_obj = BleThreadConnection(wifi_dut, ble_client)

    wlan_obj.start()
    ble_client_obj.start()
    wlan_obj.wait_for_exit()
    ble_client_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(20)
    ble_client_address = ble_client_obj.bt_client_address
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_coex_wlan_datatransfer_ble_slave_c34475(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode and BLE is in connected state as slave"""
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34475')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.MaxPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.MaxPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)

    ''' Initiating BLE connection(Slave) and should be in connected state'''
    ble_client_obj = BleThreadConnection(wifi_dut, ble_client, mode=False)

    wlan_obj.start()
    ble_client_obj.start()
    wlan_obj.wait_for_exit()
    ble_client_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(20)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_obj.ble_cli_add)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_coex_ble_wlan_datatransfer_c34476(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode with BLE and WLAN data transfer"""
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34471')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)

    ''' Initiating BLE connection(Master) and start data transfer '''
    ble_obj = BleThreadConnectionDataTransfer(wifi_dut, ble_client)

    ble_obj.start()
    wlan_obj.start()
    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(20)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_ble_connect_disconnect_wlan_datatransfer_c34477(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode with while doing BLE connect and disconnect """
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50

    # '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34477')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)
    ''' Initiating BLE connection(Master) and should be in connected state'''
    ble_client_obj = BleThreadConnectionDisconnection(wifi_dut, ble_client)

    wlan_obj.start()
    ble_client_obj.start()
    wlan_obj.wait_for_exit()
    ble_client_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(20)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_coex_wlan_datatransfer_ble_connect_disconnect_c34478(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode with while doing BLE connect and disconnect with DTIM based and monitor interval 70 """
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 70

    # '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34478')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)
    ''' Initiating BLE connection and should be in connected state'''
    ble_client_obj = BleThreadConnectionDisconnection(wifi_dut, ble_client)

    wlan_obj.start()
    ble_client_obj.start()
    wlan_obj.wait_for_exit()
    ble_client_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(20)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid

    },
)
def test_coex_ble_wlan_datatransfer_dtim_based_c34479(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, net_perf_client, protocol):
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
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

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34479')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.MaxPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.MaxPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)
    ''' Initiating BLE connection and should be able to connect & data transfer'''
    ble_client_obj = BleThreadConnectionDataTransfer(wifi_dut, ble_client)

    wlan_obj.start()
    ble_client_obj.start()
    ble_client_obj.wait_for_exit()
    wlan_obj.wait_for_exit()

    # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
    packet_filter3 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a) || ' \
                     f'(wlan.addr == {ap_bssid} && ' \
                     f'(wlan.fc.type_subtype ==8) || (wlan.fc.type_subtype==0x0028) || (wlan.fc.type_subtype==0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable -> Qos
    packet_filter4 = f'(wlan.fc.type_subtype == 0x001a || wlan.fc.type_subtype == 0x0028) || (wlan.tim.dtim_count == 0 ' \
                     f'&& wlan.tim.dtim_period == 3 && wlan.tim.aid == 0x01)'

    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']

    # Validate beacon DTIM count=0
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
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


@pytest.mark.skip
@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_coex_wlan_datatransfer_bt_enable_disable_c34485(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    ps_packet_exchange_obj = FilterPacket()
    '''Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in 
    WLAN+DUAL mode with while doing WLAN data transfer do disable and enable BT radio'''

    '''Note - https://jira.silabs.com/browse/WIFI_BT_UTFHELP-422'''
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_maxpsp_C34485')
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.start_ap()

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34485')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.MaxPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.MaxPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)
    ''' Initiating BT(Master) connection and should be in connected state'''
    bt_client_obj = BtSppThreadConnectionDataTransfer(wifi_dut, bt_client, dut_as_master=True, data_transfer=False)

    # wlan_obj.start()
    # bt_client_obj.start()
    #
    # logger().info(f'BT client address = {bt_client_obj.bt_client_address}')
    # time.sleep(15)
    # bt_disconnection_obj = BtThreadDisconnection(wifi_dut, bt_client_obj.bt_client_address)
    # bt_disconnection_obj.start()
    # wlan_obj.wait_for_exit()
    # bt_client_obj.wait_for_exit()
    # bt_disconnection_obj.wait_for_exit()

    # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
    packet_filter3 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a) || ' \
                     f'(wlan.addr == {ap_bssid} && ' \
                     f'(wlan.fc.type_subtype ==8) || (wlan.fc.type_subtype==0x0028) || (wlan.fc.type_subtype==0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable -> Qos
    packet_filter4 = f'(wlan.fc.type_subtype == 0x001a || wlan.fc.type_subtype == 0x0028) || (wlan.tim.dtim_count == 0 ' \
                     f'&& wlan.tim.dtim_period == 3 && wlan.tim.aid == 0x01)'

    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']

    # Validate beacon DTIM count=0
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_bt_wlan_datatransfer_monitor_interval_10_c34486(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 10
    '''Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in 
        WLAN+DUAL mode with BT and WLAN data transfer with monitor interval time set to 10msec'''

    # '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34486')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)
    ''' Initiating BT connection and start data transfer'''
    bt_client_obj = BtSppThreadConnectionDataTransfer(wifi_dut, bt_client, dut_as_master=True, data_transfer=True)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    bt_client_obj.start()
    bt_client_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(20)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_ble_connect_disconnect_wlan_datatransfer_c34488(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
        WLAN+DUAL mode while doing WLAN data transfer do continuous BLE connect and disconnect"""
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 10
    ''' Note this test cases has one failure 0x4b0b(SMP DH Key check failed)
        https://docs.silabs.com/rs9116-wiseconnect/latest/wifibt-wc-sapi-reference/error-codes'''

    # '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34488')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)
    ''' Initiating BT connection and should be in connected state '''
    ble_client_obj = BleThreadConnectionDisconnection(wifi_dut, ble_client)

    ble_client_obj.start()
    ble_client_obj.wait_for_exit()
    wlan_obj.start()
    wlan_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(20)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.skip
@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.Default | RS9116BTFeatureBitMap.A2DPProfileEnable | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,

    },
)
def test_coex_enhance_max_psp_C34490(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50
    '''Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in 
       WLAN+DUAL mode do WLAN and BT music streaming (A2DP profile) at weak RSSI ( less than -70dbm) '''
    ''' THIS TEST CASE REQUIRED BT HEADSET'''
    # '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34490')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)
    ''' Initiating BT connection and should be in connected state'''
    bt_client_obj = BtSppThreadA2DP(wifi_dut, bt_client)

    bt_client_obj.start()
    wlan_obj.start()
    wlan_obj.wait_for_exit()
    bt_client_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(200)
    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)
    del ps_poll_packets_time_delta_list[-1]

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.Default | RS9116BTFeatureBitMap.A2DPProfileEnable | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,

    },
)
def test_bt_wlan_datatransfer_beacon_misscount_80_C34493(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50
    '''Verify enhances max psp functionality if AP is not responding to the PS-POLL for 10msec in WLAN+DUAL mode and 
        check the wlan connection stability while doing BT and WLAN data transfer with set to RSI_REJOIN_BEACON_MISSED_COUNT
        80'''

    # '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=80, first_time_retry=0)
    time.sleep(2)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34493')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)
    ''' Initiating BT connection and should be in connected state'''
    bt_client_obj = BtSppThreadConnectionDataTransfer(wifi_dut, bt_client, dut_as_master=True, data_transfer=True)

    wlan_obj.start()
    bt_client_obj.start()
    wlan_obj.wait_for_exit()
    bt_client_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(200)
    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)
    del ps_poll_packets_time_delta_list[-1]

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.Default | RS9116BTFeatureBitMap.A2DPProfileEnable | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,

    },
)
def test_bt_wlan_datatransfer_beacon_misscount_40_C34494(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50
    '''Verify enhanced max psp functionality if AP is not responding to the PS-POLL for 10msec in WLAN+DUAL mode and 
        also check the stability of the WLAN connection while doing BT and WLAN data transfer with set to#define 
        RSI_REJOIN_BEACON_MISSED_COUNT 40'''

    # '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    time.sleep(2)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34494')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)
    ''' Initiating BT connection and should be in connected state & start data transfer'''
    bt_client_obj = BtSppThreadConnectionDataTransfer(wifi_dut, bt_client, dut_as_master=True, data_transfer=True)

    wlan_obj.start()
    bt_client_obj.start()
    wlan_obj.wait_for_exit()
    bt_client_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(200)
    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)
    del ps_poll_packets_time_delta_list[-1]

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "band": 1,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.Default | RS9116BTFeatureBitMap.A2DPProfileEnable | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
    },
)
def test_bt_wlan_datatransfer_5g_mode_C34495(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50
    ''' Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in 
            WLAN+DUAL mode while doing BT and WLAN data transfer in 5GHZ band enabled mode '''

    # '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['channel'] = 36
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34495')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)
    ''' Initiating BT connection and should be in connected state & start data transfer '''
    bt_client_obj = BtSppThreadConnectionDataTransfer(wifi_dut, bt_client, dut_as_master=True, data_transfer=True)

    wlan_obj.start()
    bt_client_obj.start()
    wlan_obj.wait_for_exit()
    bt_client_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(200)
    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)
    del ps_poll_packets_time_delta_list[-1]

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "band": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.Default | RS9116BTFeatureBitMap.A2DPProfileEnable | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
    },
)
def test_ble_slave_wlan_5g_dual_mode_C34496(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    time_delta_for_listen_interval = 1120
    filter_pack_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    monitor_interval = 50
    '''Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in 
    WLAN+DUAL mode and BLE is in connected state as slave when WLAN connected to 5GHZ band and enabled in DUAL mode band'''

    # '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['channel'] = 36
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34495')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip)
    ''' Initiating BT connection and should be in connected state'''
    bt_client_obj = BtSppThreadConnectionDataTransfer(wifi_dut, bt_client, dut_as_master=False, data_transfer=True)

    wlan_obj.start()
    bt_client_obj.start()
    wlan_obj.wait_for_exit()
    bt_client_obj.wait_for_exit()

    packet_filter1 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} ' \
                     f'&& (wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} ' \
                     f'&& (wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == 0x01)'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    time.sleep(200)
    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count']

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Create ps poll packet time delta list
    ps_poll_packets_time_delta_list = filter_pack_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)
    del ps_poll_packets_time_delta_list[-1]

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], 'Unable to find the Ps-poll/Qos Data/Null Data packets'

    logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.Default | RS9116BTFeatureBitMap.A2DPProfileEnable | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,

    },
)
def test_coex_wlan_bt_enquiry_ap_on_off_c34502(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    monitor_interval = 50
    '''Verify enhanced max psp functionality if AP is not responding to the PS-POLL for 10msec in WLAN+DUAL mode and 
        also check the stability of the WLAN connection while doing BT and WLAN data transfer with set to#define 
        RSI_REJOIN_BEACON_MISSED_COUNT 40'''

    '''BT should not stop doing inq scan when DUT lost connection from AP and while doing rejoin'''

    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='coex_enhance_max_psp_C34502')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    ''' Start ping traffic from widows machine'''
    wlan_obj = WifiPingThread(wifi_dut, device_ip)
    '''  Turn off and turn on the AP '''
    ap_obj = AccessPointApOnOff(wifi_access_point)
    ''' Initiating BT scan'''
    bt_client_obj = BtSppScan(wifi_dut, bt_client, wifi_access_point)

    wlan_obj.start()
    bt_client_obj.start()
    time.sleep(10)
    ap_obj.start()
    wlan_obj.wait_for_exit()
    bt_client_obj.wait_for_exit()
    ap_obj.wait_for_exit()


