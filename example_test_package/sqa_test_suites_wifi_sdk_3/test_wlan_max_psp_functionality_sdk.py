import re
import time
import pytest
from datetime import datetime
import datetime
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import print_dict, ping
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xAwsQos,
    Si91xCertificateType,
    Si91xModuleType,
    Si91xCertIdentifier,
    Si91xBTFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xJoinFeatureBitMap
)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


"""This test plan runs below test steps for validation of DUT-Si91x for Max-psp.
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
        1. DUT(Si91x)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's-ASUS-RTAX3000)
        5. Sniffer(NUC device)
"""


class FilterPacket:
    @staticmethod
    def get_association_id():
        """
        This function will parse the pcap file and find & return the association id
        """
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

    @staticmethod
    def delta_between_ps_poll_packet():
        """
        This function is responsible to create a list for PS-Poll packet time delta between 12 consecutive beacon
        """
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff_list = []
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

    @staticmethod
    def parse_sniffer_packets():
        """
        This function takes the filter2_file.txt as a input and parse all captured sniffer packet and convert into
        dictionary as per given input
        """
        packet_type = "    Type/Subtype:"
        packet_filter_frame = '    Frame Number:'
        packet_filter_beacon = '    Type/Subtype: Beacon frame (0x0008)'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        sniffer_dict = dict()
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
        return sniffer_dict

    @staticmethod
    def match_packet_sequence(sniffer_dict):
        """
        This function validates the packet sequence for DTIM count reaches 0(As per test case requirement need to
        validate  Beacon-> Ps-Poll-> Data packets sequentially
        """
        ps_status = False
        data_status = False
        ps_key = 0
        data_key = 0
        count = 0
        for key, value in sniffer_dict.items():
            if value == 'beacon':
                beacon_key = key
            if value == 'PS-Poll':
                if int(key) == int(beacon_key) + 1:
                    ps_key = key
                    ps_status = True
                else:
                    ps_status = False
            if value == 'Data':
                if int(key) == int(ps_key) + 1:
                    data_key = key
                    data_status = True
                else:
                    data_status = False
            if ps_status and data_status:
                logger().info(f'Sequence of TIM Beacon frame = {beacon_key}, PS-Poll = {ps_key}, Data = {data_key}\n')
                ps_status = False
                data_status = False
                count = count + 1
        return False if count == 0 else True

    @staticmethod
    def parse_sniffer_packet_more_data():
        packet_type = "    Type/Subtype:"
        packet_filter_frame = '    Frame Number:'
        packet_filter_beacon = '    Type/Subtype: Beacon frame (0x0008)'
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
        return sniffer_dict

    @staticmethod
    def validate_data_packet_with_more_bit_enable(sniffer_dict):
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

    @staticmethod
    def parse_sniffer_packet_dtim_beacon():
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
        return sniffer_dict

    @staticmethod
    def validate_packet_for_dtim_beacon(sniffer_dict, dtim_count):
        dtim1_status = False
        dtim0_status = False
        dtim_beacon_status = False
        ps_poll_status = False
        data_status = False
        status = {'wake_up_validation': True, 'sequence': False}
        dtim_wake_neg = []
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
                    counter = counter + 1

            # Note-> DTIM beacon means DTIM count = 0 & association id = 0x01
            if (value == 'DTIM_Beacon') and (key == dtim0_key + 'A') and (counter == dtim_count):
                dtim_beacon_key = key
                dtim_beacon_status = True
                match_key = dtim_beacon_key.split('A')[0]
                logger().info(dtim_beacon_key)
                counter = 0
            elif (value == 'DTIM_Beacon') and (key == dtim0_key + 'A') and (counter != dtim_count):
                counter = 0
                logger().info(key)
                logger().info('Unable to wake up at specified DTIM interval')
                dtim_wake_neg.append(key)

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

            if (dtim_beacon_status is True) and (ps_poll_status is True) and (data_status is True):
                logger().info(f'DTIM Beacon = {dtim_beacon_key}, PS-Poll = {ps_poll_key}, Qos Data = {data_key}\n\n')
                dtim_beacon_status = False
                ps_poll_status = False
                data_status = False
                counter = 0
                status['sequence'] = True
        status['dtim_wakeup_packet_list'] = dtim_wake_neg
        logger().info(f'\n\n {status}')
        if status['sequence']:
            logger().info("------------------Expected packet sequence found--------------")
            return status
        else:
            logger().info("------------------Expected packet sequence not found--------------")
            return status

    @staticmethod
    def parse_sniffer_packet_for_max_psp_95():
        """
        This function takes the filter2_file.txt as a input and parse all captured sniffer packet and convert into
        dictionary as per given input
        """

        packet_filter_frame = '    Frame Number:'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        packet_filter_dtim0 = '            DTIM count: 0'
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
        filter_file.close()
        return sniffer_dict

    @staticmethod
    def validate_packet_for_max_psp(sniffer_dict):
        """
        This function validates the packet sequence for DTIM count reaches 0(As per test case requirement need to validate
        Beacon(DTIM0)-> Ps-Poll-> Data packets sequentially
        """
        data_status = False
        ps_key = 0
        data_key = 0
        dtim0_key = 0
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
                        result = re.search('202(.*)IST', line)
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

    @staticmethod
    def parse_sniffer_packet_max_psp_95_null_frame():
        """
        This function takes the filter2_file.txt as a input and parse all captured sniffer packet and convert into
        dictionary as per given input for TC-19695
        Sequence will be PS-POLL - > Null frame + 0 -> Qos data -> Null frame + 1
        """
        packet_filter_frame = '    Frame Number:'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_null_data = '    Type/Subtype: QoS Null function (No data) (0x002c)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        packet_null = '    Type/Subtype: Null function (No data) (0x0024)'
        pmbit_0 = '            ...0 .... = PWR MGT: STA will stay up'
        pmbit_1 = '            ...1 .... = PWR MGT: STA will go to sleep'
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
        filter_file.close()
        return sniffer_dict

    @staticmethod
    def validate_packet_for_max_psp_null_frame(sniffer_dict):
        """
        This function validates the packet sequence for DTIM count reaches 0(As per test case requirement need to
        validate Beacon-> Ps-Poll-> Data packets sequentially.
        """
        pm1_status = False
        ps_key = 0
        data_key = 0
        null_key1 = 0
        null_key = 0
        pm0_status = False
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
                        result = re.search('202(.*)IST', line)
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
        if False in pass_status:
            logger().info(f'********* No packet sequence found ************')
            return False
        else:
            return True

    @staticmethod
    def validate_time_delta(ps_poll_packets_time_delta_list, time_delta_for_listen_interval):
        """
         Validates DUT is waking at listen inteval time or not and it returns the count of when DUT didn't send the
         ps_poll at listen interval
        """

        unable_to_send_ps_poll_at_li = 0
        listen_interval_beacon = int(time_delta_for_listen_interval / 100)
        for time_diff in ps_poll_packets_time_delta_list:
            is_between = time_diff in range(time_delta_for_listen_interval - 20, time_delta_for_listen_interval + 90)
            logger().info(f'is_between = {is_between}')
            if is_between is True:
                logger().info(
                    f'DUT sends PS-poll after {listen_interval_beacon} consecutive beacon frame and time diff is = {time_diff / 1000}')
            else:
                logger().info(
                    f'DUT unable to send PS-poll after {listen_interval_beacon} consecutive beacon frame and time diff is = {time_diff / 1000}')
                unable_to_send_ps_poll_at_li = unable_to_send_ps_poll_at_li + 1
        return unable_to_send_ps_poll_at_li

    @staticmethod
    def validate_pspoll_data_packet_with_more_bit_enable(frame_list, frame_number, listen_interval_time,
                                                         current_beacon_time):
        """
        Validate whether DUT is able to receive data after sending ps-poll, and it returns failed count when
        DUT didn't send ps-poll even though moredata bit set
        """
        first_beacon_time = current_beacon_time
        beacon = int('0x0008', 16)
        ps_poll = int('0x001a', 16)
        qos_data = int('0x0028', 16)
        qos_null = int('0x002c', 16)
        action_frame = int('0x000d', 16)
        block_req = int('0x0018', 16)
        no_of_filtered_packets = len(frame_list)
        case2 = 0
        while 1:
            if frame_number < no_of_filtered_packets - 2:  # removing last 2 frames from the capture
                frame_number = frame_number + 1
            else:
                break
            moredata_pspoll_failed = 0
            if ((frame_list[frame_number][2] == str(qos_data)) or (frame_list[frame_number][2] == str(qos_null)) or (
                    frame_list[frame_number][2] == str(action_frame)) or (
                    frame_list[frame_number][2] == str(block_req))):
                if (frame_list[frame_number][5]) == '1':
                    logger().info(
                        'Qos data/QOS Null frame/Action frame/block-ack req with more data bit is set to 1')
                    while 1:
                        if frame_number < no_of_filtered_packets - 2:
                            frame_number = frame_number + 1
                        else:
                            break
                        if frame_list[frame_number][2] == str(beacon):
                            current_beacon_time = float(frame_list[frame_number][1])
                            time_diff = int((current_beacon_time - first_beacon_time) * 1000)
                            if listen_interval_time == 0:
                                if frame_list[frame_number][6] == '0' and frame_list[frame_number + 1][2] == str(
                                        ps_poll) and len(frame_list[frame_number]) == 8:
                                    logger().info(
                                        "DUT is sending PS-POLL at next DTIM/DTIMSKIP beacon only even though more data bit set")
                                    case2 = case2 + 1
                                    break
                            else:
                                if time_diff >= (listen_interval_time - 30) and frame_list[frame_number + 1][2] == str(
                                        ps_poll):
                                    logger().info(
                                        "DUT is sending PS-POLL at next LI beacon only even though more data bit set")
                                    logger().info(f'time_diff={time_diff}')
                                    case2 = case2 + 1
                                    first_beacon_time = float(frame_list[frame_number][1])
                                    break
                            continue
                        elif frame_list[frame_number][2] == str(ps_poll):
                            break
                        else:
                            frame_number = frame_number - 1
                            logger().info("PS-POLL didn't observe after data packet with more data bit set")
                            break
                    continue
                else:
                    logger().info(
                        'Qos data/QOS Null frame/Action frame/block-ack req with more data bit is set to 0')
                    break
            else:
                if frame_list[frame_number][2] == str(ps_poll):
                    if moredata_pspoll_failed > 1:
                        first_beacon_time = float(frame_list[frame_number][1])
                    continue
                elif frame_list[frame_number][2] == str(beacon):
                    if frame_number < no_of_filtered_packets:
                        frame_number = frame_number + 1
                    else:
                        break
                    if ((frame_list[frame_number][2] == str(qos_data)) or (
                            frame_list[frame_number][2] == str(qos_null)) or (
                            frame_list[frame_number][2] == str(action_frame)) or (
                            frame_list[frame_number][2] == str(block_req)) or
                            frame_list[frame_number][
                                2] == str(ps_poll)):
                        continue
                    else:
                        frame_number = frame_number - 1
                        logger().info("On-air data is missing")
                        break
        return frame_number, case2, first_beacon_time

    def dtim_based_validation(self, assoc_id):
        """
        Validation of DTIM based power save functionality: DUT should send ps_poll at DTIM beacons when TIM bit set,
        and it returns the count of failed scenario's
        """
        frame_list = []
        count = 0
        assoc_id = int(assoc_id, 16)
        tim_aid = 0
        beacon = int('0x0008', 16)
        null_frame = int('0x0024', 16)
        ps_poll = int('0x001a', 16)
        ''' Validation of power save and data along with more data bit '''
        filter_file = open(f'./reports/Powersave_capture.txt', 'r')
        lines = filter_file.readlines()
        case1 = 0  # DUT should not send PS-POLL to retrieve data if TIM is not set
        case2 = 0  # DUT shouldn't wait to send PS-POLL at next DTIM beacon even though more data bit set
        case3 = 0  # DUT shouldn't skip to send PS-POLL at DTIM beacon if TIM set
        case4 = 0  # DUT should not send PS-POLL to retrieve data at non DTIM beacons
        for line in lines:
            frame_list.append(line.strip().split('\t'))
        filter_file.close()
        no_of_filtered_packets = len(frame_list)
        if no_of_filtered_packets > 10:
            no_of_filtered_packets = no_of_filtered_packets - 10  # removing last packets from capture
        if no_of_filtered_packets > 1:
            for frame_number in range(no_of_filtered_packets):
                if (frame_list[frame_number][2] == str(null_frame)) and (frame_list[frame_number][4] == '1'):
                    logger().info("found Null frame with PM '1'")
                    logger().info(frame_list[frame_number])
                    frame_number = count + 1
                    break
                else:
                    count = count + 1

        while frame_number < no_of_filtered_packets:
            if frame_list[frame_number][2] == str(beacon):
                if len(frame_list[frame_number]) == 8:
                    if len(frame_list[frame_number][7]) == 10:
                        # get the assoc id from beacon frame when TIM set
                        tim_aid = int(frame_list[frame_number][7], 16)
                    else:
                        tim_aid = frame_list[frame_number][7].split(',')
                        for j in range(len(tim_aid)):
                            if int(tim_aid[j], 16) == assoc_id:
                                tim_aid = int(tim_aid[j], 16)
                if frame_list[frame_number][6] == '0' and len(frame_list[frame_number]) == 8:
                    '''Validation of ps_poll when DTIM beacon with TIM set condition'''
                    logger().info(frame_list[frame_number])
                    dtim_flag = 0  # if TIM set at DTIM beacon and it is unable to send ps_poll to retrieve the data
                    if tim_aid == assoc_id:
                        '''Comparing  the DUT assoc id from beacon with assoc id from assoc response'''
                        while 1:
                            if frame_number < no_of_filtered_packets:
                                frame_number = frame_number + 1
                            else:
                                break
                            if frame_list[frame_number][2] == str(ps_poll):
                                if dtim_flag == 1:
                                    case3 = case3 + 1
                                    logger().info(
                                        "DUT is not sending PS-POLL to retrieve the DATA at DTIM beacon even though TIM is set")
                                logger().info(frame_list[frame_number])
                                packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_time=0,
                                    current_beacon_time=0)
                                case2 = case2 + failed_case
                                frame_number = packet_number
                                break
                            else:
                                if frame_list[frame_number][2] == str(beacon):
                                    logger().info(frame_list[frame_number])
                                    dtim_flag = 1
                                    continue
                                else:
                                    frame_number = frame_number - 1
                                    logger().info(
                                        "On-air ps-poll miss at DTIM beacon")
                                    packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                        frame_list, frame_number,
                                        listen_interval_time=0,
                                        current_beacon_time=0)
                                    case2 = case2 + failed_case
                                    frame_number = packet_number
                                    break
                elif frame_list[frame_number][6] != '0' and len(frame_list[frame_number]) == 8:
                    '''-ve scenario: Validation of ps_poll at non dtim beacons with TIM set condition'''
                    logger().info(frame_list[frame_number])
                    beacon_time = float(frame_list[frame_number][1])
                    if tim_aid == assoc_id:
                        if frame_number < no_of_filtered_packets:
                            frame_number = frame_number + 1
                        else:
                            break
                        if frame_list[frame_number][2] == str(ps_poll):
                            ps_poll_time = float(frame_list[frame_number][1])
                            time_diff = int((beacon_time - ps_poll_time) * 1000)
                            logger().info(frame_list[frame_number])
                            if time_diff > 100:
                                '''If the time difference between before beacon and current beacon is more than 100ms 
                                                                    then only we are counting as failed scenario'''
                                case4 = case4 + 1
                                logger().info("DUT is sending PS-POLL at non DTIM beacons")
                            packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                frame_list, frame_number,
                                listen_interval_time=0,
                                current_beacon_time=0)
                            case2 = case2 + failed_case
                            frame_number = packet_number
                        else:
                            if frame_list[frame_number][2] != str(beacon):
                                ps_poll_time = float(frame_list[frame_number][1])
                                time_diff = int((beacon_time - ps_poll_time) * 1000)
                                frame_number = frame_number - 1
                                if time_diff > 100:
                                    '''If the time difference between before beacon and current beacon is more than 100ms 
                                    then only we are counting as failed scenario'''
                                    case4 = case4 + 1
                                    logger().info(
                                        "On-air ps-poll miss at non DTIM beacon")
                                packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_time=0,
                                    current_beacon_time=0)
                                case2 = case2 + failed_case
                                frame_number = packet_number
                            else:
                                frame_number = frame_number - 1
                else:
                    '''-ve scenario: Validation of ps_poll when TIM is not set condition'''
                    if len(frame_list[frame_number]) != 8:
                        beacon_time = float(frame_list[frame_number][1])
                        logger().info(frame_list[frame_number])
                        if frame_number < no_of_filtered_packets:
                            frame_number = frame_number + 1
                        else:
                            break
                        if frame_list[frame_number][2] == str(ps_poll):
                            ps_poll_time = float(frame_list[frame_number][1])
                            time_diff = int((beacon_time - ps_poll_time) * 1000)
                            logger().info(frame_list[frame_number])
                            if time_diff > 100:
                                '''If the time difference between before beacon and current beacon is more than 100ms 
                                                                    then only we are counting as failed scenario'''
                                case1 = case1 + 1
                                logger().info("DUT is sending PS-POLL even though TIM is not set")
                            packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                frame_list, frame_number,
                                listen_interval_time=0,
                                current_beacon_time=0)
                            case2 = case2 + failed_case
                            frame_number = packet_number
                        else:
                            frame_number = frame_number - 1

            if frame_number < no_of_filtered_packets:
                frame_number = frame_number + 1
        return case1, case2, case3, case4

    def listen_interval_based_validation(self, listen_interval_period, assoc_id):
        """
        Validation of listen interval based power-save functionality, and it returns time interval
        b/w ps_poll, count of failed conditions
        """
        beacon_count = 0
        max_beacon = int(listen_interval_period) / 100
        frame_list = []
        dut_wake_interval = []
        count = 0
        assoc_id = int(assoc_id, 16)
        tim_aid = 0
        beacon = int('0x0008', 16)
        null_frame = int('0x0024', 16)
        ps_poll = int('0x001a', 16)
        ''' Validation of power save and data along with more data bit '''
        filter_file = open(f'./reports/Powersave_capture.txt', 'r')
        lines = filter_file.readlines()
        case1 = 0  # DUT should not send PS-POLL to retrieve data if TIM is not set
        case2 = 0  # DUT shouldn't wait to send PS-POLL at next LI beacon even though more data bit set
        for line in lines:
            frame_list.append(line.strip().split('\t'))
        filter_file.close()
        no_of_filtered_packets = len(frame_list)
        no_of_filtered_packets = no_of_filtered_packets - 10  # removing last 10 frames from the capture
        for frame_number in range(no_of_filtered_packets):
            if (frame_list[frame_number][2] == str(null_frame)) and (frame_list[frame_number][4] == '1'):
                logger().info("found Null frame with PM '1'")
                logger().info(frame_list[frame_number])
                frame_number = count + 1
                break
            else:
                count = count + 1

        first_beacon_time = float(frame_list[frame_number][1])
        while frame_number < no_of_filtered_packets:
            if frame_list[frame_number][2] == str(beacon):
                logger().info(f'beacon_count={beacon_count}')
                beacon_count = beacon_count + 1
                if beacon_count == 1:
                    logger().info(frame_list[frame_number])
                '''To get the DUT assoc id from beacon frame'''
                if len(frame_list[frame_number]) == 8:
                    if len(frame_list[frame_number][7]) == 10:
                        tim_aid = int(frame_list[frame_number][7], 16)
                    else:
                        tim_aid = frame_list[frame_number][7].split(',')
                        for j in range(len(tim_aid)):
                            if int(tim_aid[j], 16) == assoc_id:
                                tim_aid = int(tim_aid[j], 16)
                current_beacon_time = float(frame_list[frame_number][1])
                tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                '''Comparison of DUT assoc id from beacon and assoc response'''
                if tim_aid == assoc_id:
                    current_beacon_time = float(frame_list[frame_number][1])
                    tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                    '''Validation of PS-POLL at listen interval beacon with TIM set'''
                    if beacon_count == max_beacon and len(frame_list[frame_number]) == 8:
                        while 1:
                            if frame_number < no_of_filtered_packets:
                                frame_number = frame_number + 1
                            else:
                                break
                            if frame_list[frame_number][2] == str(ps_poll):
                                current_beacon_time = float(frame_list[frame_number][1])
                                tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                if beacon_count > max_beacon:
                                    dut_wake_interval.append(tim_diff_bw_beacon)
                                packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_period,
                                    current_beacon_time)
                                case2 = case2 + failed_case
                                if beacon_time == current_beacon_time:
                                    first_beacon_time = current_beacon_time
                                else:
                                    first_beacon_time = beacon_time
                                    tim_diff_bw_beacon = 0
                                frame_number = packet_number
                                break
                            else:
                                if frame_list[frame_number][2] == str(beacon):
                                    beacon_count = beacon_count + 1
                                    current_beacon_time = float(frame_list[frame_number][1])
                                    logger().info(
                                        "DUT wake at more than the LI beacon")
                                    continue

                                else:
                                    frame_number = frame_number - 1
                                    tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                    if beacon_count > max_beacon:
                                        dut_wake_interval.append(tim_diff_bw_beacon)
                                        logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                    logger().info(
                                        "On-air ps-poll miss at LI beacon")
                                    packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                        frame_list, frame_number,
                                        listen_interval_period,
                                        current_beacon_time)
                                    case2 = case2 + failed_case
                                    if beacon_time == current_beacon_time:
                                        first_beacon_time = current_beacon_time
                                    else:
                                        first_beacon_time = beacon_time
                                        tim_diff_bw_beacon = 0
                                    frame_number = packet_number
                                    break
                        beacon_count = 0
                        tim_aid = 0
                    elif ((tim_diff_bw_beacon >= (listen_interval_period - 30)) and (
                            tim_diff_bw_beacon <= listen_interval_period + 40)) and len(
                        frame_list[frame_number]) == 8:
                        '''Validation of PS-POLL at listen interval time with TIM set incase on-air beacon loss'''
                        while 1:
                            if frame_number < no_of_filtered_packets:
                                frame_number = frame_number + 1
                            else:
                                break
                            if frame_list[frame_number][2] == str(ps_poll):
                                current_beacon_time = float(frame_list[frame_number][1])
                                tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                dut_wake_interval.append(tim_diff_bw_beacon)
                                logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_period,
                                    current_beacon_time)
                                case2 = case2 + failed_case
                                if beacon_time == current_beacon_time:
                                    first_beacon_time = current_beacon_time
                                else:
                                    first_beacon_time = beacon_time
                                    tim_diff_bw_beacon = 0
                                frame_number = packet_number
                                break
                            else:
                                if frame_list[frame_number][2] == str(beacon):
                                    current_beacon_time = float(frame_list[frame_number][1])
                                    logger().info(
                                        "DUT wake at more than the LI beacon-tb")
                                    continue
                                else:
                                    frame_number = frame_number - 1
                                    tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                    dut_wake_interval.append(tim_diff_bw_beacon)
                                    logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                    logger().info(
                                        "On-air ps-poll miss at LI beacon-time difference")
                                    packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                        frame_list, frame_number,
                                        listen_interval_period,
                                        current_beacon_time)
                                    case2 = case2 + failed_case
                                    if beacon_time == current_beacon_time:
                                        first_beacon_time = current_beacon_time
                                    else:
                                        first_beacon_time = beacon_time
                                        tim_diff_bw_beacon = 0
                                    frame_number = packet_number
                                    break
                        beacon_count = 0
                        tim_aid = 0
                    else:
                        if frame_number < no_of_filtered_packets:
                            frame_number = frame_number + 1
                            if frame_list[frame_number][2] == str(ps_poll):
                                beacon_count = 0
                                tim_aid = 0
                                current_beacon_time = float(frame_list[frame_number][1])
                                tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                dut_wake_interval.append(tim_diff_bw_beacon)
                                logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                logger().info("DUT is sending PS-POLL at before/after LI beacon-time-difference")
                                packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_period,
                                    current_beacon_time)
                                case2 = case2 + failed_case
                                if beacon_time == current_beacon_time:
                                    first_beacon_time = current_beacon_time
                                else:
                                    first_beacon_time = beacon_time
                                    tim_diff_bw_beacon = 0
                                frame_number = packet_number
                            else:
                                if frame_list[frame_number][2] != str(beacon):
                                    beacon_count = 0
                                    tim_aid = 0
                                    dut_wake_interval.append(tim_diff_bw_beacon)
                                    logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                    logger().info(
                                        "DUT is waking at before LI beacon-time-difference & on-air ps-poll miss ")
                                    packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                        frame_list, frame_number,
                                        listen_interval_period,
                                        current_beacon_time)
                                    case2 = case2 + failed_case
                                    if beacon_time == current_beacon_time:
                                        first_beacon_time = current_beacon_time
                                    else:
                                        first_beacon_time = beacon_time
                                        tim_diff_bw_beacon = 0
                                    frame_number = packet_number
                                else:
                                    frame_number = frame_number - 1
                else:
                    '''Validation of -ve scenario where DUT is sending ps-poll even though TIM is not set'''
                    if frame_number < no_of_filtered_packets:
                        frame_number = frame_number + 1
                    else:
                        break
                    if frame_list[frame_number][2] == str(ps_poll):
                        beacon_count = 0
                        current_beacon_time = float(frame_list[frame_number][1])
                        tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                        dut_wake_interval.append(tim_diff_bw_beacon)
                        logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                        logger().info("DUT is sending PS-POLL even though tim is not set")
                        case1 = case1 + 1
                        packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                            frame_list, frame_number,
                            listen_interval_period,
                            current_beacon_time)
                        case2 = case2 + failed_case
                        if beacon_time == current_beacon_time:
                            first_beacon_time = current_beacon_time
                        else:
                            first_beacon_time = beacon_time
                            tim_diff_bw_beacon = 0
                        frame_number = packet_number
                    else:
                        frame_number = frame_number - 1
            else:
                if (frame_list[frame_number][2] == str(null_frame)) and (
                        (frame_list[frame_number][4] == '1') and (frame_list[frame_number][3] == '1')):
                    logger().info("found Retried Null frame with PM '1'")
                    first_beacon_time = float(frame_list[frame_number][1])
                frame_number = frame_number + 1
                continue
            if frame_number < no_of_filtered_packets:
                '''We are setting to zero for 1st beacon time and beacon count incase of TIM not set at Listen interval time'''
                if beacon_count == max_beacon or tim_diff_bw_beacon > listen_interval_period:
                    first_beacon_time = current_beacon_time
                    beacon_count = 0
                frame_number = frame_number + 1
        return dut_wake_interval, case1, case2

    def dtim_skip_based_validation(self, dtim, dtim_skip, assoc_id):
        """
        Validation of dtim skip based functionality, it should send ps-poll to retrive the data at dtim skip beacon
        and it returns time interval count of failed conditions
        """
        beacon_count = 0
        dtim_skip_itr = 0
        dtim_skip_validation = 0
        frame_list = []
        count = 0
        assoc_id = int(assoc_id, 16)
        tim_aid = 0
        beacon = int('0x0008', 16)
        ps_poll = int('0x001a', 16)
        ''' Validation of power save and data along with more data bit '''
        filter_file = open(f'./reports/Powersave_capture.txt', 'r')
        lines = filter_file.readlines()
        case1 = 0  # DUT should not send PS-POLL to retrieve data if TIM is not set
        case2 = 0  # DUT shouldn't wait to send PS-POLL at next DTIM beacon even though more data bit set
        case3 = 0  # DUT shouldn't skip to send PS-POLL at DTIMSkip beacon if TIM set
        case4 = 0  # DUT should not send PS-POLL to retrieve data at non DTIM beacons
        for line in lines:
            frame_list.append(line.strip().split('\t'))
        filter_file.close()
        no_of_filtered_packets = len(frame_list)
        no_of_filtered_packets = no_of_filtered_packets - 10  # removing last 10 frames from the capture
        for frame_number in range(no_of_filtered_packets):
            if ((str(frame_list[frame_number][2]) in ['0x0024', str(int('0x0024', 16))]) and
                    (str(frame_list[frame_number][4]).lower() in ['1', 'true'])):
                logger().info("found Null frame with PM '1'")
                logger().info(frame_list[frame_number])
                first_beacon_time = float(frame_list[frame_number][1])
                logger().info(f'first_beacon_time={first_beacon_time}')
                frame_number = count + 1
                break
            else:
                count = count + 1

        while frame_number < no_of_filtered_packets:
            current_beacon_time = float(frame_list[frame_number][1])
            tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
            logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
            if frame_list[frame_number][2] == str(beacon):
                logger().info(f'beacon_count={beacon_count}')
                beacon_count = beacon_count + 1
                if beacon_count == 1:
                    logger().info(frame_list[frame_number])
                    dtim_period = int(dtim) - 1
                    first_beacon_validation = dtim_period - int(frame_list[frame_number][6])
                    dtim_skip_validation = (int(dtim) * dtim_skip) - first_beacon_validation
                    logger().info(f'DUT should wake at {dtim_skip_validation} beacon')
                    if dtim_skip_itr == 0:  # for first wake after enabled power save
                        expected_time_to_wake = 102 * dtim_skip_validation
                        logger().info(f'expected_time_to_wake={expected_time_to_wake}')
                    else:
                        expected_time_to_wake = 102 * (int(dtim) * dtim_skip)
                        logger().info(f'expected_time_to_wake={expected_time_to_wake}')
                '''To get the DUT assoc id from beacon frame'''
                if len(frame_list[frame_number]) == 8:
                    if len(frame_list[frame_number][7]) == 10:
                        tim_aid = int(frame_list[frame_number][7], 16)
                    else:
                        tim_aid = frame_list[frame_number][7].split(',')
                        for j in range(len(tim_aid)):
                            if int(tim_aid[j], 16) == assoc_id:
                                tim_aid = int(tim_aid[j], 16)
                dtim_flag = 0  # if TIM set at DTIM beacon and it is unable to send ps_poll to retrieve the data
                if beacon_count == dtim_skip_validation and frame_list[frame_number][6] == '0' and len(
                        frame_list[frame_number]) == 8:
                    '''Validation of ps_poll when DTIM skip beacon with TIM set condition'''
                    if tim_aid == assoc_id:
                        while 1:
                            if frame_number < no_of_filtered_packets:
                                frame_number = frame_number + 1
                            else:
                                break
                            if frame_list[frame_number][2] == str(ps_poll):
                                if dtim_flag == 1:
                                    case3 = case3 + 1
                                    logger().info(
                                        "DUT is not sending PS-POLL to retrieve the DATA at DTIM beacon even though TIM is set")
                                packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_time=0,
                                    current_beacon_time=0)
                                case2 = case2 + failed_case
                                frame_number = packet_number
                                break
                            else:
                                if frame_list[frame_number][2] == str(beacon):
                                    beacon_count = beacon_count + 1
                                    current_beacon_time = float(frame_list[frame_number][1])
                                    logger().info(
                                        "DUT wake at more than the LI beacon")
                                    dtim_flag = 1
                                    continue

                                else:
                                    frame_number = frame_number - 1
                                    logger().info(
                                        "On-air ps-poll miss at LI beacon")
                                    packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                        frame_list, frame_number,
                                        listen_interval_time=0,
                                        current_beacon_time=0)
                                    case2 = case2 + failed_case
                                    frame_number = packet_number
                                    break
                        beacon_count = 0
                elif (expected_time_to_wake + 30 > tim_diff_bw_beacon > expected_time_to_wake - 30) and len(
                        frame_list[frame_number]) == 8 and frame_list[frame_number][6] == '0':
                    ''' Validation of ps_poll at dtim skip beacon time with TIM set condition in case of on-air beacon miss'''
                    logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                    if tim_aid == assoc_id:
                        while 1:
                            if frame_number < no_of_filtered_packets:
                                frame_number = frame_number + 1
                            else:
                                break
                            if frame_list[frame_number][2] == str(ps_poll):
                                if dtim_flag == 1:
                                    case3 = case3 + 1
                                    logger().info(
                                        "DUT is not sending PS-POLL to retrieve the DATA at DTIM beacon even though TIM is set")
                                packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_time=0,
                                    current_beacon_time=0)
                                case2 = case2 + failed_case
                                frame_number = packet_number
                                break
                            else:
                                if frame_list[frame_number][2] == str(beacon):
                                    beacon_count = beacon_count + 1
                                    current_beacon_time = float(frame_list[frame_number][1])
                                    logger().info(
                                        "DUT wake at more than the LI beacon")
                                    dtim_flag = 1
                                    continue

                                else:
                                    frame_number = frame_number - 1
                                    logger().info(
                                        "On-air ps-poll miss at LI beacon")
                                    packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                        frame_list, frame_number,
                                        listen_interval_time=0,
                                        current_beacon_time=0)
                                    case2 = case2 + failed_case
                                    frame_number = packet_number
                                    break
                        beacon_count = 0
                else:
                    '''-ve scenario: validation of ps-poll when DUT wake at non dtim/dtim skip beacons'''
                    if len(frame_list[frame_number]) == 8 and tim_aid == assoc_id:
                        if frame_number < no_of_filtered_packets:
                            frame_number = frame_number + 1
                            if frame_list[frame_number][2] == str(ps_poll):
                                ps_poll_time = float(frame_list[frame_number][1])
                                time_diff_bw_beacon_pspoll = int((ps_poll_time - first_beacon_time) * 1000)
                                logger().info(f'time_diff_bw_beacon_pspoll={time_diff_bw_beacon_pspoll}')
                                if (
                                        expected_time_to_wake + 30 > time_diff_bw_beacon_pspoll > expected_time_to_wake - 30):
                                    '''If the time difference between beacon and ps-poll is more than expected time to wake
                                                                                                        then only we are counting as failed scenario'''
                                    logger().info(
                                        "on-air beacons got miss")
                                else:
                                    case4 = case4 + 1
                                    logger().info(
                                        "DUT is sending PS-POLL to retrieve the data other than the expected time/beacon to wake")
                                packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_time=0,
                                    current_beacon_time=0)
                                case2 = case2 + failed_case
                                frame_number = packet_number
                                beacon_count = 0
                            elif frame_list[frame_number][2] != str(beacon):
                                data_packet_time = float(frame_list[frame_number][1])
                                time_diff_bw_beacon_data = int((data_packet_time - first_beacon_time) * 1000)
                                logger().info(f'time_diff_bw_beacon_data={time_diff_bw_beacon_data}')
                                if expected_time_to_wake + 30 < time_diff_bw_beacon_data < expected_time_to_wake - 30:
                                    '''If the time difference between beacon and ps-poll is more than expected time to wake
                                       then only we are counting as failed scenario'''
                                    logger().info(
                                        "on-air beacon&ps-poll miss to retrieve the data other than the expected time/beacon to wake")
                                else:
                                    case4 = case4 + 1
                                    logger().info(
                                        "DUT is sending PS-POLL to retrieve the data other than the expected time/beacon to wake")

                                packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_time=0,
                                    current_beacon_time=0)
                                case2 = case2 + failed_case
                                frame_number = packet_number
                                beacon_count = 0
                            else:
                                frame_number = frame_number - 1
                    else:
                        '''-ve csenario:Validation ps-poll & data at when TIM not set case'''
                        if frame_number < no_of_filtered_packets:
                            frame_number = frame_number + 1
                            if frame_list[frame_number][2] == str(ps_poll):
                                '''-ve scenario: Validation of ps_poll when TIM is not set condition'''
                                ps_poll_time = float(frame_list[frame_number][1])
                                time_diff_bw_beacon_pspoll = int((ps_poll_time - first_beacon_time) * 1000)
                                logger().info(f'time_diff_bw_beacon_pspoll={time_diff_bw_beacon_pspoll}')
                                if (
                                        expected_time_to_wake + 30 < time_diff_bw_beacon_pspoll < expected_time_to_wake - 30):
                                    '''If the time difference between beacon and ps-poll is more than expected time to wake
                                                                                                        then only we are counting as failed scenario'''
                                    logger().info(
                                        "on-air beacons got miss")
                                else:
                                    case1 = case1 + 1
                                    logger().info(
                                        "DUT is sending PS-POLL to retrieve the data even though TIM is not set at expected beacon to wake")

                                packet_number, failed_case, beacon_time = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_time=0,
                                    current_beacon_time=0)
                                case2 = case2 + failed_case
                                frame_number = packet_number
                                beacon_count = 0
                            else:
                                frame_number = frame_number - 1
            if (
                    beacon_count == dtim_skip_validation or expected_time_to_wake - 30 < tim_diff_bw_beacon < expected_time_to_wake + 30) \
                    and len(frame_list[frame_number]) != 8:
                '''We are restting the beacon count to '0' if beacon count reaches to DTIM skip validation beacon or time without TIM set in AP beacon'''
                beacon_count = 0
            if frame_number < no_of_filtered_packets:
                frame_number = frame_number + 1
            if beacon_count == 0:
                tim_aid = 0
                dtim_skip_itr = dtim_skip_itr + 1
                first_beacon_time = current_beacon_time
        return case1, case2, case3, case4


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={"beacon_interval": 100, "dtim": 3})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_max_psp_listen_interval_11ms_c40154(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections):
    """
    Verify whether RSI_STA is wake up and receive data based on configured listen interval when enable power save
    2 & MAX PSP mode and set listen_interval_dtim is 0.
    Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons
    """
    listen_interval = 1100
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    powersave_validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_sdk_max_psp_listen_interval_11ms_c40154')

    wifi_dut.interfaces.wifi.set_join_feature_bitmap(Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
    wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
    result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                                                 associated=False)
    device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info(f"***** Enabling Max PSP in DUT ******")
    wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', dtim_aligned_type=0,
                                                     num_of_dtim_skip=0, listen_interval=listen_interval,
                                                     monitor_interval=50)
    wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                  psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

    logger().info("Pinging to DUT to with byte size 300")
    status = sl_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=300)
    assert status, "DUT is not responding to ping request after powersave"

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    # Assoc resp frame in sniffer to get the DUT assoc id
    packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
        'packet_count'], 'No packet found for Assoc resp frame'

    time.sleep(1)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                     f' (wlan.da == {ap_bssid}))'

    packet_filter3 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                     f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                     f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                     f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None, powersave_validation)[
        'packet_count']
    ps_poll_packets_time_delta_list, case1, case2 = ps_poll_time_delta_obj.listen_interval_based_validation(
        listen_interval,
        association_id)
    case3 = ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, listen_interval)
    if case1 != 0:
        logger().info(
            f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
    if case2 != 0:
        logger().info(
            f'Observed {case2} times DUT is sending the PS-POLL to retrieve the data after post listen interval beacon only even though more data bit is set')
    if case3 != 0:
        logger().info(
            f'Observed {case3} times DUT is unable to send PS-POLL at listen interval')

    if case1 or case3 > 3 or case2 != 0:
        assert False
    else:
        assert True, "DUT is sending PS-POLL to retrieve the data at Listen interval beacon only"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={"beacon_interval": 100, "dtim": 3})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_max_psp_dtim_3_c40155(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections):
    """
    Verify whether RSI_STA is wake up and receive data at DTIM beacon when enable power save2 & MAX PSP mode
    """

    validation = True
    powersave_validation = True
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    ps_packet_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_sdk_max_psp_dtim_3_c40155')

    wifi_dut.interfaces.wifi.set_join_feature_bitmap()
    result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                                                 associated=False)
    device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info(f"***** Enabling Max PSP in DUT ******")
    wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', dtim_aligned_type=0,
                                                     num_of_dtim_skip=0,
                                                     monitor_interval=50)
    wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                  psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

    logger().info("Pinging to DUT to with byte size 300")
    status = sl_collections.ping_with_custom_size(device_ip, ping_counts=30, byte_size=300)
    assert status, "DUT is not responding to ping request after powersave"

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    # Assoc resp frame in sniffer
    packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
        'packet_count'], 'No packet found for Assoc resp frame'

    time.sleep(1)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
    packet_filter4 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                     f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                     f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                     f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, None, powersave_validation)[
        'packet_count']
    # ps_poll_packets_time_delta_list, case1, case2 = assoc_obj.DTIM_Based_validation(association_id)
    case1, case2, case3, case4 = ps_packet_exchange_obj.dtim_based_validation(association_id)
    if case1: logger().info(
        f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
    if case2: logger().info(
        f'Observed {case2} times DUT is sending PS-POLL at next DTIM beacon even though more data bit set')
    if case3: logger().info(
        f'Observed {case3} times DUT is not sending PS-POLL at DTIM beacon even though TIM is set')
    if case4: logger().info(
        f'Observed {case4} times DUT is sending PS-POLL at non-DTIM beacons')

    if case1 or case4 or case3 > 3 or case2 != 0:
        assert False
    else:
        assert True, "DUT is sending PS-POLL to retrieve the data at DTIM beacon only"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={"beacon_interval": 100, "dtim": 3})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_max_psp_dtim_3_c40156(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections):
    """
    Configure the AP DTIM count=2 and DUT DTIM no. of skip = 3 validate when DTIM count reach 0 DUT
    should wake up and send PS poll & data packet, second validation is check Qos data will send again after Ps-Poll
    if More data bit is set to 1
    """
    validation = True
    powersave_validation = True
    dtim_skip = 4
    dtim_beacon_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    dtim = 3

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_sdk_max_psp_dtim_3_c40156')

    wifi_dut.interfaces.wifi.set_join_feature_bitmap(Si91xJoinFeatureBitMap.Default)
    result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                                                 associated=False)
    device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info(f"***** Enabling Max PSP in DUT ******")
    wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', dtim_aligned_type=1,
                                                     num_of_dtim_skip=dtim_skip - 1, monitor_interval=50)
    wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                  psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

    logger().info("Pinging to DUT to with byte size 300")
    status = sl_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=300)
    assert status, "DUT is not responding to ping request after powersave"

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    #  DUT Assoc ID from Assoc resp frame in sniffer
    packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
        'packet_count'], 'No packet found for Assoc resp frame'

    time.sleep(1)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    # Power save mode 1
    packet_filter3 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
    packet_filter4 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                     f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                     f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                     f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'No packet found for Power save mode 1/Null frame'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, None, powersave_validation)[
        'packet_count'], 'Unable to find any  PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c) packets'
    case1, case2, case3, case4 = dtim_beacon_obj.dtim_skip_based_validation(dtim, dtim_skip, association_id)
    if case1: logger().info(
        f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
    if case2: logger().info(
        f'Observed {case2} times DUT is sending PS-POLL at next DTIM beacon even though more data bit set')
    if case3: logger().info(
        f'Observed {case3} times DUT is not sending PS-POLL at DTIM Skip beacon even though TIM is set')
    if case4: logger().info(
        f'Observed {case4} times DUT is sending PS-POLL at non-DTIM beacons')
    if case1 or case4 or case3 > 3 or case2 != 0:
        assert False
    else:
        assert True, "DUT is sending PS-POLL to retrieve the data at DTIM skip beacon only"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={"dtim": 2})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_max_psp_enable_disable_c40157(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                utf_constants):
    """
    Verify the power save mode2 functionality enable and disable while doing data transfer for overnight
    """
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_join_feature_bitmap(Si91xJoinFeatureBitMap.Default)
    result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                                                 associated=False)
    device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    # Power save mode 1
    packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address})' \
                     f'and (wlan.da == {ap_bssid}))'
    # Power save mode 0
    packet_filter3 = f'(wlan.fc.pwrmgt == 0) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address})' \
                     f'and (wlan.da == {ap_bssid}))'

    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_sdk_max_psp_enable_disable_c40157')
    try:
        test_run_time = utf_constants.get('time_duration')
        sw = Stopwatch()
        while sw.elapsed_sec < test_run_time:
            time_left = int((test_run_time - sw.elapsed_sec) / 60)
            logger().info(f"\n\nRemaining time to complete test is '{time_left}' minutes")
            logger().info(f"***** Enabling Max PSP in DUT ******")
            wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', dtim_aligned_type=0,
                                                             num_of_dtim_skip=0, monitor_interval=50)
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

            logger().info("Pinging to DUT to with byte size 300")
            status = sl_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=300)
            assert status, "DUT is not responding to ping request after powersave"

            logger().info(f"***** Disable Max PSP in DUT ******")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveDisabled,
                                                          psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            time.sleep(2)
            logger().info("Pinging to DUT to with byte size 300")
            status = sl_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=300)
            assert status, "DUT is not responding to ping request after powersave"
    except Exception as error:
        logger().error("Failed in enabling and disabling power save.")
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'No packet found for pwmt bit enable'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'No packet found for pwmt bit disable'

