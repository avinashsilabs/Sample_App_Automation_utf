import re
import time
from datetime import datetime, timedelta
import datetime
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.bluetooth import BTSocketRole
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
    RS9116PowerSaveProcedureTypes
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,

)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


# This Thread is used to run the dut on Master mode
class BtSppConnectThread(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        self.logger.info('this is bt run')
        # BT as Master and connect to remote BT[raspi] & validation for connect and disconnect multiple times
        for i in range(0, 1):
            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None
            time.sleep(2)
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None
            time.sleep(0.5)

            # Added set class to 400100 to avoid [Errno 112] Host is down issue
            self.bt_client.interfaces.bluetooth.bt_adapter.set_class('400100')

            with self.bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Client
            ) as bt_client_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_client_socket.create_client()
                    result = ThreadBase.call_functions_simultaneously(
                        [(self.wifi_dut.interfaces.wifi.bt_connect, bt_client_address), (bt_client_socket.accept, 20)])
                    assert result[1] == bt_dut_address
                    logger().info(f"Result from Callable Function {result}")
            time.sleep(1)
            self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
            time.sleep(2)


class WifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut, net_perf_client, protocol, device_ip):
        super().__init__()
        self.iperf_obj = FilterPacket()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.device_ip = device_ip

    def run(self):
        time.sleep(5)
        self.iperf_obj.start_iperf_dut_as_server(self.wifi_dut, self.net_perf_client, self.protocol, self.device_ip)


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

    def connection_bt_spp_master_slave(self, wifi_dut, wifi_access_point, bt_client, dut_as_master=True,
                                       data_transfer=False):
        send_text = "sA0L9b1xEgGuUqN5YOlx" * 10
        recv_text = "H2D7yZKRhKULU9Xil5Yv" * 10
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

                    # Check for data transfer
                    if data_transfer:
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


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
    },
)
def test_coex_enhance_max_psp_C34467(wifi_sniffer, wifi_access_point, wifi_dut, net_perf_client, protocol):
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
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
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
def test_coex_enhance_max_psp_C34468(wifi_sniffer, wifi_access_point, wifi_dut, net_perf_client, protocol):
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
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
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
def test_coex_enhance_max_psp_C34469(wifi_sniffer, wifi_access_point, wifi_dut, net_perf_client, protocol):
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
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
    },
)
def test_coex_enhance_max_psp_C34470(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
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

    ''' Initiating BT connection & send data '''
    bt_client_address = filter_pack_obj.connection_bt_spp_master_slave(wifi_dut, wifi_access_point, bt_client,
                                                                       dut_as_master=True, data_transfer=False)

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    filter_pack_obj.start_iperf_dut_as_server(wifi_dut, net_perf_client, protocol, device_ip)

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
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
    },
)
def test_coex_enhance_max_psp_C34471(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
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

    ''' Initiating BT connection, DUT as a Master & send/receive data '''
    bt_client_address = filter_pack_obj.connection_bt_spp_master_slave(wifi_dut, wifi_access_point, bt_client,
                                                                       dut_as_master=True, data_transfer=True)

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

    time.sleep(20)
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
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
    },
)
def test_coex_enhance_max_psp_C34472(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
     WLAN+DUAL mode and BT is in connected state as a slave """
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

    ''' Initiating BT connection and DUT as a Slave '''
    bt_client_address = filter_pack_obj.connection_bt_spp_master_slave(wifi_dut, wifi_access_point, bt_client,
                                                                       dut_as_master=False, data_transfer=False)

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    filter_pack_obj.start_iperf_dut_as_server(wifi_dut, net_perf_client, protocol, device_ip)

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
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
    },
)
def test_coex_enhance_max_psp_C34473(wifi_sniffer, wifi_access_point, wifi_dut, bt_client, net_perf_client, protocol):
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

    # Call a thread to execute BT and WLAN simultaneously
    with WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip), BtSppConnectThread(wifi_dut, bt_client):
        logger().info(f'Run thread')

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
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
    },
)
def test_coex_enhance_max_psp_C34474(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, net_perf_client, protocol):
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
                                        power_save_type=RS9116PowerSaveProcedureTypes.MaxPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.MaxPowerSave
    )

    ''' Initiating BT connection, DUT as a Master & send/receive data '''
    ble_client_address = filter_pack_obj.connection_ble_spp_master_slave(wifi_dut, ble_client,
                                                                         dut_as_master=True, data_transfer=False)

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

    time.sleep(20)
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
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
    },
)
def test_coex_enhance_max_psp_C34475(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, net_perf_client, protocol):
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
                                        power_save_type=RS9116PowerSaveProcedureTypes.MaxPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.MaxPowerSave
    )

    ''' Initiating BT connection, DUT as a Master & send/receive data '''
    ble_client_address = filter_pack_obj.connection_ble_spp_master_slave(wifi_dut, ble_client,
                                                                         dut_as_master=False, data_transfer=False)

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

    time.sleep(20)
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
