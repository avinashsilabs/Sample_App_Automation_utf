import re
import time
from datetime import datetime, timedelta
import datetime
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
import pytest
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, ping
from utf.utils.logger import get_logger
import time
import pytest
from numpy import arange

# from utils.logger import get_logger
import pytest as pytest
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116DataRate, RS9116RejoinParams, RS9116JoinFeatureBitMap, \
    RS9116ULPModes, RS9116PowerSaveProcedureTypes, RS9116ExtCustomFeatureBitMap

from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,

)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


"""This test plan runs below test steps for validation of DUT-RS9116 for Max-psp.
        1. Configuration of DUT in 2G : BGN
        2. Configure AP as per test case requirement(DTIM/Beacon interval)
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Verification of basic power save/pm bit enable or not
        6. Validation of DTIM interval/Listen Interval/Monitor interval for different power save category(PS 1/2/3) in LP/ULP mode.
        7. Validation of power save enable/disable test cases for long duration(12 hours).
        8. Validation of power save in different traffic category.
        9. Validation of power save mode with different AP(Netgear WNR1000,TP-LINK(TL-WDR5620),ASUS-LYRA, Xfinity XB3 
           ,Xfinity XB6 & Belkin AP). Note -  User need to configure the AP manually and update in harness file for test execution. 
        10. Power save 3 test cases are still need assistance, configuration not clear. 


    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's-ASUS-RTAX3000)
        5. Sniffer(NUC device)
"""


class IopTcpIpSockets:
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

    def connect_socket(self, wifi_dut, tcp_socket_id: int):
        retry_limit: int = 2
        connect_status = False
        for retry in range(1, retry_limit):
            connect_response = wifi_dut.interfaces.wifi.connect(tcp_socket_id)
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


class FilterPacket:
    def get_association_id(self):
        # This function will parse the pacap file and find & return the association id
        packet_filter = "= Association ID:"
        association_id = None
        count = 0

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                association_id = x.strip().split(':')[1].strip()
                print(f'Association id = {association_id}')
                break
        filter_file.close()
        return association_id

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

    def validate_packet_for_dtim_beacon(self, sniffer_dict, dtim_wake_up):
        dtim1_status = False
        dtim0_status = False
        dtim_beacon_status = False
        ps_poll_status = False
        data_status = False
        status = {'wake_up_validation': True, 'sequence': False}
        data_key = 0
        ps_poll_key = 0
        dtim1_key = 0
        dtim0_key = 0
        counter = 0
        match_key = 0

        for key, value in sniffer_dict.items():
            # Note-> DTIM1 means DTIM count = 1
            if value == 'DTIM1' or ((value == 'DTIM1') and (int(key) == int(dtim0_key) + 1)):
                dtim1_key = key
                dtim1_status = True

            # Note-> DTIM0 means DTIM count = 0
            if value == 'DTIM0':
                if (int(key) == int(dtim1_key) + 1) and (dtim1_status is True):
                    dtim0_key = key
                    dtim0_status = True
                    if counter < dtim_wake_up:
                        counter = counter + 1

            # Note-> DTIM beacon means DTIM count = 0 & association id = 0x01
            if (value == 'DTIM_Beacon') and (key == dtim0_key + 'A') and (counter == dtim_wake_up):
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

            # if DTIM count is 0 then check TIM bit is 0(means association id should not be present in TIM bit)
            # or not if not then DUT should not send PS-POLL
            if dtim0_status is True and dtim_beacon_status is False:
                if int(ps_poll_key) == int(dtim0_key) + 1:
                    logger().info("Validating wake up indication when TIM bit is not set")
                    status['wake_up_validation'] = False

            # if DTIM count is nonzero then check DUT should not send any PS-POLL
            # Logic is DUT should not wake up or send PS-POLL packets in Non DTIM beacon intervals
            # So next packet should not be PS-POLL packet
            if dtim1_status is True:
                if int(ps_poll_key) == int(dtim1_key) + 1:
                    logger().info("Validating wake up indication at non DTIM intervals")
                    status['wake_up_validation'] = False

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

            if (dtim_beacon_status is True) and (ps_poll_status is True) and (data_status is True):
                logger().info(f'DTIM Beacon = {dtim_beacon_key}, PS-Poll = {ps_poll_key}, Qos Data = {data_key}\n\n')
                dtim_beacon_status = False
                ps_poll_status = False
                data_status = False
                counter = 0
                status['sequence'] = True
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

    def validate_packet_for_max_psp_null_frame(self, sniffer_dict):
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
                expected_time_between_ps_poll_and_data_frame = 0.070
                if float(time_diff_in_ms) <= expected_time_between_ps_poll_and_data_frame:
                    logger().info(
                        f"\nTime difference between Qos data frame = {time_diff_list[0]} & NUll frame with pm bit 1 = "
                        f"{time_diff_list[1]} is less than 70ms \n")
                    pass_status.append(True)
                else:
                    logger().info(
                        f"Time difference between Qos data frame = {time_diff_list[0]} & NUll frame with pm bit 1 = "
                        f"{time_diff_list[1]} is greater than 50ms")
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

    def validate_time_delta(self, ps_poll_packets_time_delta_list, time_delta_for_listen_interval):
        list_status = []
        ps_poll_packets_time_delta_list.pop(0)
        del ps_poll_packets_time_delta_list[-1]
        logger().info(f'\n\n PS-poll packet time delta list after removing 0 = {ps_poll_packets_time_delta_list}')
        for time_diff in ps_poll_packets_time_delta_list:
            time_diff = int(round(time_diff, 3) * 1000)
            is_between = time_diff in range(time_delta_for_listen_interval, time_delta_for_listen_interval + 10)
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


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
    },
)
def test_maxpsp_listen_interval_12ms_c40148(wifi_sniffer, wifi_access_point, wifi_dut):
    time_delta_for_listen_interval = 1220
    monitor_interval = 50
    assoc_obj = FilterPacket()
    ps_poll_time_delta_obj = FilterPacket()
    validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
<<<<<<< HEAD
    ping_count = 10
=======
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab

    '''Validate listen interval from DUT side, DUT should wake up and send data after 12 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_maxpsp_C40148')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1200)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(1, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Initiate ping from third party wifi-client to DUT
<<<<<<< HEAD
    status = ping(device_ip, ping_count)
=======
    status = ping(device_ip, 10)
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab
    assert status

    # Assoc resp frame in sniffer
    packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
        'packet_count']

    time.sleep(5)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                     f' (wlan.da == {ap_bssid}))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == {association_id})'

    packet_filter4 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                     f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} && ' \
                     f'(wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'
    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter5 = f'wlan.fc.type_subtype == 0x001a'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter11)[
        'packet_count']

    # Validate the time delta between PS-poll packet
    ps_poll_packets_time_delta_list = ps_poll_time_delta_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
    },
)
def test_max_psp_dtim_3_c40149(wifi_sniffer, wifi_access_point, wifi_dut):
    validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
    assoc_obj = FilterPacket()
    ps_packet_exchange_obj = FilterPacket()
    ping_count = 20

    '''Configure the AP DTIM count=3 and validate when DTIM count reach 0 DUT should wake up and send PS poll & data
    packet, second validation is check Qos data will send again after Ps-Poll if More data bit is set to 1'''
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_maxpsp_C40149')
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.start_ap()

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(1, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Initiate ping from third party wifi-client to DUT
    status = ping(device_ip, ping_count)
    assert status

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # Assoc resp frame in sniffer
    packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
        'packet_count']

    time.sleep(5)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
    packet_filter3 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a) || ' \
                     f'(wlan.addr == {ap_bssid} && ' \
                     f'(wlan.fc.type_subtype ==8) || (wlan.fc.type_subtype==0x0028) || (wlan.fc.type_subtype==0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable -> Qos
    packet_filter4 = f'(wlan.fc.type_subtype == 0x001a || wlan.fc.type_subtype == 0x0028) || (wlan.tim.dtim_count == 0 ' \
                     f'&& wlan.tim.dtim_period == 3 && wlan.tim.aid == {association_id})'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']

    # Validate beacon DTIM count=0
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter11)[
        'packet_count']

    logger().info('-----------Validation for DTIM count = 0 sequence---------------- ')
    sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packets()
    assert ps_packet_exchange_obj.match_packet_sequence(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                       'Beacon(DTIM count=0)-> Ps-Poll-> Data'

    logger().info('-----------Validation for More data bit sequence---------------- ')
    sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packet_more_data()
    assert ps_packet_exchange_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
        'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
    },
)
def test_max_psp_dtim_4_c40150(wifi_sniffer, wifi_access_point, wifi_dut):
    validation = True
    dtim_beacon_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
    dtim_wake_up = 5
<<<<<<< HEAD
    ping_count = 50
=======
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab

    '''Configure the AP DTIM count=2 and DUT DTIM no. of skip = 4 validate when DTIM count reach 0 DUT
    should wake up and send PS poll & data packet, second validation is check Qos data will send again after Ps-Poll
    if More data bit is set to 1'''
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(5)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_maxpsp_C40150')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=1, monitor_interval=50,
                                                  number_of_dtim_skip=4)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(1, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Initiate ping from third party wifi-client to DUT
<<<<<<< HEAD
    status = ping(device_ip, ping_count)
=======
    status = ping(device_ip, 50)
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab
    assert status

    #  DUT Assoc ID from Assoc resp frame in sniffer
    packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
        'packet_count']

    time.sleep(5)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    # broadcast probe requests from DUT
    packet_filter2 = f'(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} and ' \
                     f'wlan.da == ff:ff:ff:ff:ff:ff)'

    # Power save mode 1
    packet_filter3 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    # validate data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c)
    packet_filter4 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                     f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.addr == {ap_bssid} && ' \
                     f'(wlan.fc.type_subtype==8 || wlan.fc.type_subtype == 0x002c))'

    # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
    packet_filter5 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a) || ' \
                     f'(wlan.addr == {ap_bssid} && ' \
                     f'(wlan.fc.type_subtype ==8) || (wlan.fc.type_subtype==0x0028) || (wlan.fc.type_subtype==0x002c))'

    time.sleep(2)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'No packet found for broad cast probe requests from DUT'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'No packet found for Power save mode 1/Null frame'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find any  PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c) packets'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter11)[
        'packet_count'], 'No packet found for Beacon, Ps-Poll, Qos Data'

    logger().info('-----------Parse the sniffer packet and store in dictionary for DTIM beacon-----------------\n\n ')
    sniffer_dict = dtim_beacon_obj.parse_sniffer_packet_dtim_beacon()

    logger().info('-----------Validation for 5th DTIM beacon sequence----------------\n\n')
    status = dtim_beacon_obj.validate_packet_for_dtim_beacon(sniffer_dict, dtim_wake_up)
    assert all(status.values()), 'No sequence found for sniffer packets 5th DTIM beacon-> Ps-Poll-> Data'

    logger().info('-----------Parse the sniffer packet and store in dictionary for more data bit----------------\n\n ')
    sniffer_dict = dtim_beacon_obj.parse_sniffer_packet_more_data()
    logger().info('-----------Validation for more data bit----------------\n\n ')
    assert dtim_beacon_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
        'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
    },
)
def test_max_psp_lp_mode_c40152(wifi_sniffer, wifi_access_point, wifi_dut):
    time_delta_for_listen_interval = 1220
    monitor_interval = 50
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    filter_pack_obj = FilterPacket()
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
    validation = True
<<<<<<< HEAD
    ping_count = 30
=======
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab

    '''Validate listen interval from DUT side, DUT should wake up and send data after 12 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_maxpsp_C40152')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1200)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Initiate ping from third party wifi-client to DUT
<<<<<<< HEAD
    status = ping(device_ip, ping_count)
=======
    status = ping(device_ip, 30)
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab
    assert status

    # broadcast probe requests from DUT
    packet_filter4 = f'(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} and ' \
                     f'wlan.da == ff:ff:ff:ff:ff:ff)'

    #  DUT Assoc ID from Assoc resp frame in sniffer
    packet_filter5 = f'(wlan.fc.type_subtype == 0x0001) and (wlan.sa == {ap_bssid} and wlan.da == {dut_mac_address})'

    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter10)[
        'packet_count']

    time.sleep(5)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    # Power save mode 1
    packet_filter6 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter1 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == {association_id})'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter3 = f'wlan.fc.type_subtype == 0x001a'

    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find Probe request packet from DUT'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find DUT Assoc ID from Assoc resp frame in sniffer'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
        'packet_count'], 'Unable to find PM bit 1 in sniffer packet'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association-id and PS-poll packet with pm bit enable in beacon'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter11)[
        'packet_count'], 'Unable to find PS-Poll packet'

    # time.sleep(5)
    # Validate the time delta between PS-poll packet
    ps_poll_packets_time_delta_list = ps_poll_time_delta_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert filter_pack_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
    },
)
def test_max_psp_ulp_c40153(wifi_sniffer, wifi_access_point, wifi_dut):
    time_delta_for_listen_interval = 1220
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
<<<<<<< HEAD
    ping_count = 10
=======
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab

    '''Validate listen interval from DUT side, DUT should wake up and send data after 12 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')


    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_maxpsp_C40153')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1200)

    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Initiate ping from third party wifi-client to DUT
<<<<<<< HEAD
    status = ping(device_ip, ping_count)
=======
    status = ping(device_ip, 10)
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab
    assert status

    logger().info('\n\n Time sleep ! Wait for 60 seconds......')
    time.sleep(60)

    #  DUT Assoc ID from Assoc resp frame in sniffer
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0001) and (wlan.sa == {ap_bssid} and wlan.da == {dut_mac_address})'

    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
        'packet_count']

    time.sleep(5)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    # Power save mode 1
    packet_filter3 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
        'Unable to find PM bit 1 in packets'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter11)[
        'packet_count'], 'Unable to find PS-Poll packet'

    time.sleep(5)
    # Validate the time delta between PS-poll packet
    ps_poll_packets_time_delta_list = ps_poll_time_delta_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
    },
)
def test_maxpsp_listen_interval_11ms_c40154(wifi_sniffer, wifi_access_point, wifi_dut):
    time_delta_for_listen_interval = 1120
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
<<<<<<< HEAD
    ping_count = 10
=======
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab

    '''Verify whether RSI_STA is wake up and receive data based on configured listen interval when enable power save 
       2 & MAX PSP mode and set listen_interval_dtim is 0'''
    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=50,
                                                  number_of_dtim_skip=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_maxpsp_C40154')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Initiate ping from third party wifi-client to DUT
<<<<<<< HEAD
    status = ping(device_ip, ping_count)
=======
    status = ping(device_ip, 10)
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab
    assert status

    # Assoc resp frame in sniffer
    packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
        'packet_count']

    time.sleep(5)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.(for manual QA ref.)
    packet_filter3 = f'(wlan.ta == {dut_mac_address} && wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1) || ' \
                     f'(wlan.fc.type_subtype == 0x0008 || wlan.tim.aid == {association_id})'

    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter11)[
        'packet_count']

    # Validate the time delta between PS-poll packet
    ps_poll_packets_time_delta_list = ps_poll_time_delta_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_max_psp_dtim_3_c40155(wifi_sniffer, wifi_access_point, wifi_dut):
    validation = True
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    ps_packet_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()
    ping_count = 20

    '''Verify whether RSI_STA is wake up and receive data at DTIM beacon when enable power save2 & MAX PSP mode'''
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=50,
                                                  number_of_dtim_skip=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_maxpsp_C40155')
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.start_ap()

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)
    wifi_dut.interfaces.wifi.start_ip()
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Initiate ping from third party wifi-client to DUT
    status = ping(device_ip, ping_count)
    assert status

    # Assoc resp frame in sniffer
    packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
        'packet_count'], 'No packet found for Assoc resp frame'

    time.sleep(5)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable -> Qos
    packet_filter3 = f'(wlan.fc.type_subtype == 0x001a || wlan.fc.type_subtype == 0x0028) || (wlan.tim.dtim_count == 0 ' \
                     f'&& wlan.tim.dtim_period == 3 && wlan.tim.aid == {association_id})'

    # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
    packet_filter4 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a) || ' \
                     f'(wlan.addr == {ap_bssid} && ' \
                     f'(wlan.fc.type_subtype ==8) || (wlan.fc.type_subtype==0x0028) || (wlan.fc.type_subtype==0x002c))'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find any packet from beacon with association-id and PS-poll packet'

    # Validate beacon DTIM count=0
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter11)[
        'packet_count'], 'Unable to find beacon DTIM count 0'

    logger().info('-----------Validation for DTIM count = 0 sequence---------------- ')
    sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packets()
    assert ps_packet_exchange_obj.match_packet_sequence(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                       'Beacon(DTIM count=0)-> Ps-Poll-> Data'

    logger().info('-----------Validation for More data bit sequence---------------- ')
    sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packet_more_data()
    assert ps_packet_exchange_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
        'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
    },
)
def test_max_psp_dtim_3_c40156(wifi_sniffer, wifi_access_point, wifi_dut):
    validation = True
    dtim_wake_up = 4
    dtim_beacon_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
<<<<<<< HEAD
    ping_count = 50
=======
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab

    '''Configure the AP DTIM count=2 and DUT DTIM no. of skip = 3 validate when DTIM count reach 0 DUT
    should wake up and send PS poll & data packet, second validation is check Qos data will send again after Ps-Poll
    if More data bit is set to 1'''
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(5)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_maxpsp_C40156')
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=1, monitor_interval=50,
                                                  number_of_dtim_skip=3)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Initiate ping from third party wifi-client to DUT
<<<<<<< HEAD
    status = ping(device_ip, ping_count)
=======
    status = ping(device_ip, 50)
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab
    assert status

    # broadcast probe requests from DUT
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} and ' \
                     f'wlan.da == ff:ff:ff:ff:ff:ff)'

    #  DUT Assoc ID from Assoc resp frame in sniffer
    packet_filter3 = f'(wlan.fc.type_subtype == 0x0001) and (wlan.sa == {ap_bssid} and wlan.da == {dut_mac_address})'

    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter10)[
        'packet_count'], 'No packet found for Assoc resp frame'

    time.sleep(5)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    # Power save mode 1
    packet_filter4 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
    packet_filter5 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a) || ' \
                     f'(wlan.addr == {ap_bssid} && ' \
                     f'(wlan.fc.type_subtype ==8) || (wlan.fc.type_subtype==0x0028) || (wlan.fc.type_subtype==0x002c))'

    time.sleep(2)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'No packet found for broad cast probe requests from DUT'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'No packet found for Power save mode 1/Null frame'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter11)[
        'packet_count'], 'No packet found for Beacon, Ps-Poll, Qos Data'

    logger().info('-----------Parse the sniffer packet and store in dictionary for DTIM beacon-----------------\n\n ')
    sniffer_dict = dtim_beacon_obj.parse_sniffer_packet_dtim_beacon()

    logger().info('-----------Validation for 4th DTIM beacon sequence----------------\n\n')
    status = dtim_beacon_obj.validate_packet_for_dtim_beacon(sniffer_dict, dtim_wake_up)
    assert all(status.values()), 'No sequence found for sniffer packets 5th DTIM beacon-> Ps-Poll-> Data'

    logger().info('-----------Parse the sniffer packet and store in dictionary for more data bit----------------\n\n ')
    sniffer_dict = dtim_beacon_obj.parse_sniffer_packet_more_data()
    logger().info('-----------Validation for more data bit----------------\n\n ')
    assert dtim_beacon_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
        'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
    },
)
def test_max_psp_enable_disable_c40157(wifi_sniffer, wifi_access_point, wifi_dut):
    validation = True
    ping_count = 20

    '''Verify the power save mode2 functionality enable and disable while doing data transfer for overnight'''
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(5)

    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=50,
                                                  number_of_dtim_skip=0)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    # Power save mode 1
    packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    # Power save mode 0
    packet_filter3 = f'(wlan.fc.pwrmgt == 0) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    wifi_sniffer.interfaces.capture.start_capture(capture_file='enable_maxpsp_C40157')
    end_time = datetime.datetime.now() + timedelta(minutes=12)
    start_time = datetime.datetime.now()
    try:
        while datetime.datetime.now() < end_time:
            logger().info(f"*****Enable Max PSP in DUT******")
            wifi_dut.interfaces.wifi.power_save(2, 0)
            wifi_dut.interfaces.wifi.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )

            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, ping_count)
            assert status

            logger().info(f"*****Disable Max PSP in DUT******")
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled,
                                                RS9116PowerSaveProcedureTypes.MaxPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveDisabled
            )
            time.sleep(2)

            status = ping(device_ip, ping_count)
            assert status
    except():
        assert False, "Power save enable disable failure"
    finally:
        end_time = datetime.datetime.now()
        exact_execution_time = end_time - start_time
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'No packet found for pwmt bit enable'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'No packet found for pwmt bit disable'
        logger().info(f"********* Total execution time of test case = {exact_execution_time}**********")


'''*********************************POWER SAVE 3 TEST CASES************************************************'''


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.firmware_app("test_wlan_powersave_mode")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
    },
)
def test_power_save3_c40160(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut):
    validation = True
    ping_count = 20

    '''Verify RSI_STA is going to power save or not when enable power save mode3 with LP mode and MAX PSP'''
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(5)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='powersave3_C40160')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=50,
                                                  number_of_dtim_skip=0)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'
    # Power save mode 3
    packet_filter3 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    logger().info(f"*****Enable Power save mode 3 Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    time.sleep(30)
    # Initiate ping from third party wifi-client to DUT
    status = ping(device_ip, ping_count)
    assert status

    wifi_sniffer.interfaces.capture.stop_capture()
    # time.sleep(2)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'No packet found'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'No packet found for pwmt bit enable'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.firmware_app("test_wlan_powersave_mode")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
    },
)
def test_power_save3_c40161(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut):
    validation = True
    ping_count = 20

    '''Verify RSI_STA is going to power save or not when enable power save mode 3 with ULP mode with RAM retention and 
       MAX PSP'''
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(5)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='powersave3_C40161')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=50,
                                                  number_of_dtim_skip=0)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'
    # Power save mode 3
    packet_filter3 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    logger().info(f"*****Enable Power save mode 3 Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    time.sleep(30)
    # Initiate ping from third party wifi-client to DUT
    status = ping(device_ip, ping_count)
    assert status

    wifi_sniffer.interfaces.capture.stop_capture()
    # time.sleep(2)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'No packet found for pwmt bit enable'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'No packet found for pwmt bit enable'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.firmware_app("test_wlan_powersave_mode")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
    },
)
def test_power_save3_listen_interval_c40162(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut):
    time_delta_for_listen_interval = 1120
    ps_poll_time_delta_obj = FilterPacket()
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    ping_count = 20

    '''Verify whether RSI_STA is wake up and receive data based on configured listen interval when enable power save3 
       & MAX PSP mode and set listen_interval_dtim is 0'''
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(5)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='powersave3_C40162')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=50,
                                                  number_of_dtim_skip=0)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.
                                     ListenIntervalFromJoin,
                                     listen_interval=1100)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'
    # Power save mode 3
    packet_filter3 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    packet_filter4 = f'wlan.fc.type_subtype == 0x001a'

    logger().info(f"*****Enable Power save mode 3 Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(30)
    # Initiate ping from third party wifi-client to DUT
    status = ping(device_ip, ping_count)
    assert status

    wifi_sniffer.interfaces.capture.stop_capture()
    # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive beacon packets)

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'No packet found'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'No packet found for pwmt bit enable'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    time.sleep(5)
    # Validate the time delta between PS-poll packet
    ps_poll_packets_time_delta_list = ps_poll_time_delta_obj.delta_between_ps_poll_packet()
    logger().info(ps_poll_packets_time_delta_list)

    # Validate the time delta between PS-poll packet
    assert ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.firmware_app("test_wlan_powersave_mode")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
    },

)
def test_power_save3_dtim_c40163(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut):
    validation = True
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
    ps_packet_exchange_obj = FilterPacket()
    ping_count = 20

    '''Verify whether RSI_STA is wake up and receive data at DTIM beacon when enable power save 3 & MAX PSP mode'''
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(5)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='dtim_powersave3_C40163')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=50,
                                                  number_of_dtim_skip=0)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Power save mode 3 Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    packet_filter1 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid}'
    # Power save mode 3
    packet_filter3 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
    packet_filter4 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a) || ' \
                     f'(wlan.addr == {ap_bssid} && ' \
                     f'(wlan.fc.type_subtype ==8) || (wlan.fc.type_subtype==0x0028) || (wlan.fc.type_subtype==0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable -> Qos
    packet_filter5 = f'(wlan.fc.type_subtype == 0x001a || wlan.fc.type_subtype == 0x0028) || (wlan.tim.dtim_count == 0 ' \
                     f'&& wlan.tim.dtim_period == 3 && wlan.tim.aid == 0x01)'

    time.sleep(30)
    # Initiate ping from third party wifi-client to DUT
    status = ping(device_ip, ping_count)
    assert status

    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find any packet'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'No packet found for pwmt bit enable'

    # Validate beacon DTIM count=0
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)[
        'packet_count']

    # Validate beacon DTIM count=0
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter2)[
        'packet_count']

    logger().info('-----------Validation for DTIM count = 0 sequence---------------- ')
    sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packets()
    assert ps_packet_exchange_obj.match_packet_sequence(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                       'Beacon(DTIM count=0)-> Ps-Poll-> Data'

    logger().info('-----------Validation for More data bit sequence---------------- ')
    sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packet_more_data()
    assert ps_packet_exchange_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
        'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.firmware_app("test_wlan_powersave_mode")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
    },

)
def test_power_save3_c40164(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut):
    validation = True
    dtim_wake_up = 5
    dtim_beacon_obj = FilterPacket()
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'
<<<<<<< HEAD
    ping_count = 50
=======
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab

    '''Verify whether RSI_STA is able to wakeup and receive data at 4th DTIM beacon when we configure num_of_dtim_skip
       is 3 with power save mode 3 with MAX PSP and set listen_interval_dtim is 1'''
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(5)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='dtim_powersave3_C40164')
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=1, monitor_interval=50,
                                                  number_of_dtim_skip=4)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Power save mode 3 Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Initiate ping from third party wifi-client to DUT
<<<<<<< HEAD
    status = ping(device_ip, ping_count)
=======
    status = ping(device_ip, 50)
>>>>>>> c3c3094eb86f3f668226635529d56e950afb62ab
    assert status

    # broad cast probe requests from DUT
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} and ' \
                     f'wlan.da == ff:ff:ff:ff:ff:ff)'

    #  DUT Assoc ID from Assoc resp frame in sniffer
    packet_filter3 = f'(wlan.fc.type_subtype == 0x0001) and (wlan.sa == {ap_bssid} and wlan.da == {dut_mac_address})'

    # Power save mode 1
    packet_filter4 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
    packet_filter5 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a) || ' \
                     f'(wlan.addr == {ap_bssid} && ' \
                     f'(wlan.fc.type_subtype ==8) || (wlan.fc.type_subtype==0x0028) || (wlan.fc.type_subtype==0x002c))'

    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()
    time.sleep(2)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'No packet found for broad cast probe requests from DUT'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'No packet found for Assoc resp frame'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'No packet found for Power save mode 1/Null frame'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter2)[
        'packet_count'], 'No packet found for Beacon, Ps-Poll, Qos Data'

    logger().info('-----------Parse the sniffer packet and store in dictionary for DTIM beacon-----------------\n\n ')
    sniffer_dict = dtim_beacon_obj.parse_sniffer_packet_dtim_beacon()

    logger().info('-----------Validation for 5th DTIM beacon sequence----------------\n\n')
    status = dtim_beacon_obj.validate_packet_for_dtim_beacon(sniffer_dict, dtim_wake_up)
    assert all(status.values()), 'No sequence found for sniffer packets 5th DTIM beacon-> Ps-Poll-> Data'

    logger().info('-----------Parse the sniffer packet and store in dictionary for more data bit----------------\n\n ')
    sniffer_dict = dtim_beacon_obj.parse_sniffer_packet_more_data()
    logger().info('-----------Validation for more data bit----------------\n\n ')
    assert dtim_beacon_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
        'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.firmware_app("test_wlan_powersave_mode")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
    },
)
def test_power_save3_enable_disable_c40165(firmware_loader, wifi_sniffer, wifi_access_point, wifi_dut):
    validation = True
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    ping_count = 20

    '''Verify the power save mode3 functionality enable and disable while doing data transfer for overnight'''
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(5)
    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=50,
                                                  number_of_dtim_skip=0)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    # Power save mode 1
    packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    # Power save mode 0
    packet_filter3 = f'(wlan.fc.pwrmgt == 0) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    wifi_sniffer.interfaces.capture.start_capture(capture_file='ps3_overnight_C40165')
    end_time = datetime.datetime.now() + timedelta(minutes=5)
    start_time = datetime.datetime.now()
    try:
        while datetime.datetime.now() < end_time:
            logger().info(f"*****Enable Max PSP in DUT******")
            wifi_dut.interfaces.wifi.power_save(2, 1)
            wifi_dut.interfaces.wifi.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )
            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, ping_count)
            assert status

            logger().info(f"*****Disable Max PSP in DUT******")
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled,
                                                RS9116PowerSaveProcedureTypes.MaxPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveDisabled
            )
            time.sleep(2)
            status = ping(device_ip, ping_count)
            assert status
    except():
        assert False, "Power save enable disable failure"
    finally:
        end_time = datetime.datetime.now()
        exact_execution_time = end_time - start_time
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'No packet found for pwmt bit enable'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'No packet found for pwmt bit disable'
        logger().info(f"********* Total execution time of test case = {exact_execution_time}**********")
