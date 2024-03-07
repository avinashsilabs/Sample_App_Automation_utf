import re
import time
from utf.utils.stopwatch import Stopwatch
from utf.utils.time_measurer import TimeMeasurer
import pytest as pytest
from utf import UtfDatabaseProperties
from utf.utils.iperf.iperf_utils import ping
from test_wlan_data_rates_sdk import SocketDataTransfer
import threading
from threading import Thread, Event
from utf.utils.thread_base import ThreadBase
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.shell.ssh_shell import SSHShell
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import print_dict
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
    Si91xJoinFeatureBitMap,
    IEEE802_11W,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes
)

from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


"""Author : Vivek"""

"""This test plan runs below test steps for validation of DUT-RS917 for Max-psp/Enhanced max psp.
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
        1. DUT(RS917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's-ASUS-RTAX3000)
        4. Sniffer(NUC device)
"""


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None, time_period=None
                 , data_transfer=True, test_name=None, sl_collections=None, net_perf_client=None, wifi_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.time_period = time_period
        self.data = 'Thisisfromclient'
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                             time_period=self.time_period, data=self.data)

    def run(self):
        try:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            if self.test_case_no == 19678:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , ping_after_power_save=False,
                                                                         mode='power_save',
                                                                         listen_interval=1200)
            if self.test_case_no == 19679:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , ping_after_power_save=False,
                                                                         mode='power_save',
                                                                         dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, listen_interval=1100)

            if self.test_case_no == 19680:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , ping_after_power_save=False,
                                                                         mode='power_save',
                                                                         dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0)

            if self.test_case_no == 19682:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , ping_after_power_save=False,
                                                                         power_save=False)

            if self.test_case_no == 19693:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, mode='power_save',
                                                                         listen_interval=1200)

            if self.test_case_no == 19694:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, mode='power_save')
            if self.test_case_no == 19694:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, mode='power_save')

            if self.test_case_no == 19695:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=70,
                                                                         num_of_dtim_skip=0, mode='power_save',
                                                                         listen_interval=1200)

            if self.test_case_no == 19696:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=100,
                                                                         num_of_dtim_skip=0, mode='power_save',
                                                                         listen_interval=1200)

            if self.test_case_no == 19697:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, mode='power_save',
                                                                         listen_interval=600)

            if self.test_case_no == 19698:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0,
                                                                         ping_after_power_save=False,
                                                                         power_save=False)

            if self.test_case_no == 19699:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, listen_interval=1200,
                                                                         mode='power_save')

            if self.test_case_no == 196700:
                qos_value = ['0x00', '0x20', '0x80', '0xC8']
                traffic = '0x00'
                protocol = 'TCP'
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, listen_interval=1200)

                for qos in qos_value:
                    host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                    logger().info(f"Remote device ip :{host_ip}")
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                         device_ip=self.dut_addr['device_ip'],
                                                                         protocol=protocol)
                    logger().info(
                        f"Host IP: {host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {protocol}, "
                        f"tos_value: {traffic}")
                    logger().info(f"***** starting iperf ******")

                    def start_client():
                        time.sleep(1)
                        logger().info(f"***** start listening  ******")
                        self.net_perf_client.interfaces.net_perf.start()

                    client_thread1 = Thread(target=start_client, args=(), )
                    client_thread1.start()

                    logger().info(f"***** send traffic  ******")
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=1460, ttl=30, throughput_type=2, qos=qos)
                    logger().info(f"***** get and print throughput ******")
                    # tp = self.net_perf_client.interfaces.net_perf.process_output()
                    # assert tp, "failed to get throughput..."
                    # __print_throughput(tp)
                    logger().info("data received is successful")
                    time.sleep(5)

            if self.test_case_no == 196703:
                self.wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11n", data_rate='72.2Mbps',
                                                                expected_status=SLStatus.SL_STATUS_OK)

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, listen_interval=1200,
                                                                         mode='power_save')

            if self.test_case_no == 196704:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, listen_interval=1200,
                                                                         mode='power_save')

            if self.test_case_no == 196705:
                qos_value = '0x00'
                traffic = '0x00'
                protocol = 'TCP'
                wait_time = [60, 300]
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, listen_interval=1200,
                                                                         mode='power_save')

                '''Send traffic RX for 1/5 min'''
                for iperf_run_time in wait_time:
                    host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                    logger().info(f"Remote device ip :{host_ip}")
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                         device_ip=self.dut_addr['device_ip'],
                                                                         protocol=protocol)
                    logger().info(
                        f"Host IP: {host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {protocol}, "
                        f"tos_value: {traffic}")
                    logger().info(f"***** starting iperf ******")

                    def start_client():
                        time.sleep(1)
                        logger().info(f"***** start listening  ******")
                        self.net_perf_client.interfaces.net_perf.start()

                    client_thread1 = Thread(target=start_client, args=(), )
                    client_thread1.start()

                    logger().info(f"***** send traffic  ******")
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=1460, ttl=iperf_run_time, throughput_type=2, qos='0x00')
                    logger().info(f"***** get and print throughput ******")
                    # tp = self.net_perf_client.interfaces.net_perf.process_output()
                    # assert tp, "failed to get throughput..."
                    # __print_throughput(tp)
                    logger().info("data received is successful")
                    time.sleep(5)
                    client_thread1.wait_for_exit()
                    time.sleep(25)
            if self.test_case_no == 196706:
                qos_value = '0x00'
                traffic = '0x00'
                protocol = 'TCP'
                wait_time = [60, 300]
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, mode='power_save')

                '''Send traffic RX for 1/5 min'''
                for iperf_run_time in wait_time:
                    host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                    logger().info(f"Remote device ip :{host_ip}")
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                         device_ip=self.dut_addr['device_ip'],
                                                                         protocol=protocol)
                    logger().info(
                        f"Host IP: {host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {protocol}, "
                        f"tos_value: {traffic}")
                    logger().info(f"***** starting iperf ******")

                    def start_client():
                        time.sleep(1)
                        logger().info(f"***** start listening  ******")
                        self.net_perf_client.interfaces.net_perf.start()

                    client_thread1 = Thread(target=start_client, args=(), )
                    client_thread1.start()

                    logger().info(f"***** send traffic  ******")
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=1460, ttl=iperf_run_time, throughput_type=2, qos='0x00')
                    logger().info(f"***** get and print throughput ******")
                    # tp = self.net_perf_client.interfaces.net_perf.process_output()
                    # assert tp, "failed to get throughput..."
                    # __print_throughput(tp)
                    logger().info("data received is successful")
                    time.sleep(5)
                    client_thread1.wait_for_exit()
                    time.sleep(25)

            logger().info("DUT successfully connected with AP")
            time.sleep(2)
            if self.data_transfer:
                self.socket_obj.socket_data_transfer()

            time.sleep(1)
            # self.wifi_dut.interfaces.wifi.leave()
        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e


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

    def validate_packet_for_dtim_beacon(self, sniffer_dict, dtim_count):
        dtim1_status = False
        dtim_wake_neg = []
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
            is_between = time_diff in range(time_delta_for_listen_interval, time_delta_for_listen_interval + 40)
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_max_psp_ulp_c19678(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                            request, utf_constants):
    time_delta_for_listen_interval = 1100
    test_name = request.node.name
    test_case_no = 19678
    time_period = utf_constants.get("time_period")
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Validate listen interval from DUT side, DUT should wake up and send data after 12 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info('\n\n Time sleep ! Wait for 60 seconds......')
        time.sleep(60)
        wifi_sniffer.interfaces.capture.stop_capture()

        #  DUT Assoc ID from Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count']

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Power save mode 1
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        da_addr=ap_bssid,
                                                                                        filter_name='power_mgmt_bit')
        logger().info(f'\n\n *** FILTER 3 ={packet_filter3} *** \n')

        # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive
        # beacon packets)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (ta_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name='ps_poll_delta')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find PM bit 1 in packets'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter11)[
            'packet_count'], 'Unable to find PS-Poll packet'

        time.sleep(5)
        # Validate the time delta between PS-poll packet
        ps_poll_packets_time_delta_list = ps_poll_time_delta_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list,
                                                          time_delta_for_listen_interval)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_maxpsp_listen_interval_11ms_c19679(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                                            request, utf_constants):
    test_name = request.node.name
    test_case_no = 19679
    time_period = utf_constants.get("time_period")
    time_delta_for_listen_interval = 1100
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
    list_status = []
    '''Verify whether RSI_STA is wake up and receive data based on configured listen interval when enable power save
       2 & MAX PSP mode and set listen_interval_dtim is 0'''
    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    time.sleep(5)
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()
        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count']

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.
        # (for manual QA ref.)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_bssid, association_id=association_id,
            filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_assoc_id')

        logger().info(f'\n\n *** FILTER 3 ={packet_filter3} *** \n')

        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (ta_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name='ps_poll_delta')
        logger().info(f'\n\n *** FILTER 4 ={packet_filter4} *** \n')

        # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive
        # beacon packets)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count']
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter11)[
            'packet_count']

        # Validate the time delta between PS-poll packet
        ps_poll_packets_time_delta_list = ps_poll_time_delta_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list,
                                                          time_delta_for_listen_interval)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_max_psp_dtim_3_c19680(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                               request, utf_constants):
    test_name = request.node.name
    test_case_no = 19680
    time_period = utf_constants.get("time_period")
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    ps_packet_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()

    '''Configure the AP DTIM count=3 and validate when DTIM count reach 0 DUT should wake up and send PS poll & data
    packet, second validation is check Qos data will send again after Ps-Poll if More data bit is set to 1'''
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.start_ap()

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count']

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable -> Qos
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            association_id=association_id,
            filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_qos_dtim_3')

        # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            da_addr=ap_bssid, filter_name='beacon_assoc_id_dtim_count_ps_poll_with_pm_bit_enable')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count'], 'Unable to find any packet from beacon with association-id and PS-poll packet'

        # Validate beacon DTIM count=0
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter11)[
            'packet_count'], 'Unable to find beacon DTIM count 0'

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


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_max_psp_enable_disable_c19682(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                                       request, utf_constants):
    test_name = request.node.name
    test_case_no = 19682
    count = 0
    time_period = utf_constants.get("time_period")
    '''Verify the power save mode2 functionality enable and disable while doing data transfer for overnight'''
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    mode = 'power_save'

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, data_transfer=False)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='enable_maxpsp_C19682')

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            da_addr=ap_bssid, filter_name='power_mgmt_bit')

        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=
                                                                                        wlan_obj.dut_addr[
                                                                                            'dut_mac_address'],
                                                                                        da_addr=ap_bssid,
                                                                                        filter_name='power_mgmt_bit_disable')
        end_time = 400
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        sw = Stopwatch()
        while sw.elapsed_sec < end_time:
            logger().info(f"\n\n EL time = {sw.elapsed_sec}, END time = {end_time} *\n")
            logger().info(f"\n\n *****Enable Max PSP in DUT******\n")
            logger().info(f"....Applying performance profile mode : {mode}")
            wifi_dut.interfaces.wifi.set_performance_profile(mode=mode, monitor_interval=50)
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            status = ping(device_ip, 20)
            assert status == 1

            '''Disable the Power save mode'''
            time.sleep(10)
            logger().info(f"\n\n *****Disable Max PSP in DUT******\n")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            time.sleep(25)
            status = ping(device_ip, 20)
            assert status == 1
            count = count + 1
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'No packet found for pwmt bit enable'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count'], 'No packet found for pwmt bit disable'
        logger().info(f"\n\n *** NO of iteration = {count}\n\n")

    except():
        logger().info(f"\n\n *** NO of iteration = {count}\n\n")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_enhanced_max_psp_ulp_c19693(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                                     request, utf_constants):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19693
    time_delta_for_listen_interval = 1100
    ps_poll_time_delta_obj = FilterPacket()
    ps_packet_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Verify the DUT functionality when ULP POWER SAVE MODE 2,Enhanced MAX PSP and LISTEN INTERVAL based power
    save feature enabled.'''

    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        time.sleep(25)
        wifi_sniffer.interfaces.capture.stop_capture()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            da_addr=ap_bssid, filter_name='power_mgmt_bit')

        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        wlan_addr=ap_bssid,
                                                                                        filter_name='coex_enhanced_max_psp_34469')
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (ta_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name='ps_poll_delta')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'No packet found'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count'], 'No packet found for pwmt bit enable'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter11)[
            'packet_count'], 'No packet found for pwmt bit enable'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packet_more_data()
        assert ps_packet_exchange_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5,
                                                                  packet_filter2=packet_filter11)[
            'packet_count'], 'No sequence found for 12 consecutive beacon'

        time.sleep(5)
        # Validate the time delta between PS-poll packet
        ps_poll_packets_time_delta_list = ps_poll_time_delta_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list,
                                                          time_delta_for_listen_interval)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_enhanced_max_psp_c19694(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                                 request, utf_constants):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19694
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    ps_packet_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()

    '''Verify whether DUT is waking up before every DTIM Beacon, when ULP POWER SAVE MODE 2, Enhanced MAX PSP and
       DTIM based power save features are enabled.'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'Device IP = {device_ip}')

        # validate association response packet with association id
        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        time.sleep(100)
        wifi_sniffer.interfaces.capture.stop_capture()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # validate NULL data frame with PM bit set to '1'
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'],
             da_addr=ap_bssid, filter_name='power_mgmt_bit')

        '''Configure the AP DTIM count=3 and validate when DTIM count reach 0 DUT should wake up and send PS poll & data
        packet'''
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            association_id=association_id,
            filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_qos_dtim_3')

        ''' validate data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c) '''
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        wlan_addr=ap_bssid,
                                                                                        filter_name='coex_enhanced_max_psp_34469')
        time.sleep(200)

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count'], 'Unable to find validate NULL data frame with PM bit set to 1'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find association -id for DTIM count reach 3'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6,
                                                                  packet_filter2=packet_filter11)[
            'packet_count'], 'Unable to find data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c)'

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info(
            '---------2. Validation for PS-Poll & Qos Data packet time difference should be within 20ms -------- ')
        sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packet_for_max_psp_95()
        assert ps_packet_exchange_obj.validate_packet_for_max_psp(
            sniffer_dict), 'No sequence found for sniffer packets ' \
                           'Beacon(DTIM count 0)->PS-POLL->Qos data ' \
                           'packet '

        '''Second validation is check Qos data will send again after Ps-Poll if More data bit is set to 1'''
        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packet_more_data()
        assert ps_packet_exchange_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_enhanced_max_psp_c19695(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                                 request, utf_constants):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19695
    frame_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Verify the DUT functionality when ULP POWER SAVE MODE 2, Enhanced MAX PSP with monitor interval 70 and LISTEN
       INTERVAL based power save features are enabled.(TC_2).			'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info('\n\n Time sleep ! Wait for 200 seconds......')
        time.sleep(200)
        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        wifi_sniffer.interfaces.capture.stop_capture()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(1)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.
        # (for manual QA ref.)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_bssid, association_id=association_id,
            filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_assoc_id')

        # validate data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        wlan_addr=ap_bssid,
                                                                                        filter_name='coex_enhanced_max_psp_34469')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count'], 'Unable to find beacon with association-id and PS-poll packet with pm bit enable'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                  packet_filter2=packet_filter11)[
            'packet_count'], 'Unable to find Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c)'

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_for_max_psp_95()
        result = frame_exchange_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                               'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_more_data()
        assert frame_exchange_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference---------------- ')
            sniffer_dict = frame_exchange_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert frame_exchange_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict), 'No sequence found for sniffer packets ' \
                               'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info('***** Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & '
                          'Qos Data packet time difference passed successfully')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_enhanced_max_psp_c19696(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                                 request, utf_constants):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19696
    frame_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Verify the DUT functionality when ULP POWER SAVE MODE 2, FAST PSP with monitor interval 100 and LISTEN INTERVAL
       based power save features are enabled'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info('\n\n Time sleep ! Wait for 200 seconds......')
        time.sleep(200)

        wifi_sniffer.interfaces.capture.stop_capture()

        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # validate data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        wlan_addr=ap_bssid,
                                                                                        filter_name='coex_enhanced_max_psp_34469')

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.
        # (for manual QA ref.)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_bssid,
                                                                                        association_id=association_id,
                                                                                        filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_assoc_id')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                  packet_filter2=packet_filter11)[
            'packet_count'], 'Unable to find data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), ' \
                             'Qos NUll data(0x002c) packets'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count'], 'Unable to find beacon with association-id and PS-poll packet with pm bit enable'

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_for_max_psp_95()
        result = frame_exchange_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                               'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_more_data()
        assert frame_exchange_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 '
                'data packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference---------------- ')
            sniffer_dict = frame_exchange_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert frame_exchange_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict), 'No sequence found for sniffer packets ' \
                               'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info('***** Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & '
                          'Qos Data packet time difference passed successfully')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_enhanced_max_psp_c19697(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                                 request, utf_constants):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19697
    frame_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Verify the functionality of DUT when ULP POWER SAVE MODE 2, FAST PSP and listen interval is changed in power
       save command to 600 msec'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info('\n\n Time sleep ! Wait for 200 seconds......')
        time.sleep(200)

        wifi_sniffer.interfaces.capture.stop_capture()

        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.
        # (for manual QA ref.)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_bssid,
                                                                                        association_id=association_id,
                                                                                        filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_assoc_id')
        # validate data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        wlan_addr=ap_bssid,
                                                                                        filter_name='coex_enhanced_max_psp_34469')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count'], 'Unable to find beacon with association-id and PS-poll packet with pm bit enable'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter11)[
            'packet_count'], 'Unable to find data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), ' \
                             'Qos NUll data(0x002c) packets'

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_for_max_psp_95()
        result = frame_exchange_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                               'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_more_data()
        assert frame_exchange_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 '
                'data packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference------------- ')
            sniffer_dict = frame_exchange_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert frame_exchange_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict), 'No sequence found for sniffer packets ' \
                               'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info('***** Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & '
                          'Qos Data packet time difference passed successfully')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_max_psp_enable_disable_c19698(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                                       request, utf_constants):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19698
    mode = 'power_save'
    count = 0
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'

    '''Verify the power save mode2 functionality enable and disable while doing data transfer for overnight'''
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        # Power save mode 1
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'],
             da_addr=ap_bssid, filter_name='power_mgmt_bit')

        # Power save mode 0
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'],
             da_addr=ap_bssid, filter_name='power_mgmt_bit_disable')

        wifi_sniffer.interfaces.capture.start_capture(capture_file='enhance_maxpsp_C19698')

        end_time = 300
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        sw = Stopwatch()
        while sw.elapsed_sec < end_time:
            logger().info(f"\n\n *****Enable Max PSP in DUT******\n")
            wifi_dut.interfaces.wifi.set_performance_profile(mode=mode)
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            status = ping(device_ip, 20)
            assert status == 1

            '''Disable the Power save mode'''
            time.sleep(100)
            logger().info(f"\n\n *****Disable Max PSP in DUT******\n")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            time.sleep(50)
            status = ping(device_ip, 20)
            assert status == 1
            count = count + 1
        logger().info(f"\n\n *** NO of iteration = {count}\n\n")
    except():
        logger().info(f"\n\n *** NO of iteration = {count}\n\n")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'No packet found for pwmt bit enable'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count'], 'No packet found for pwmt bit disable'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_enhanced_max_psp_with_diff_ap_c19699(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                                              request, utf_constants):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19699
    frame_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Note - Please use preconfigured different AP's, with same ssid as you mentioned in Harness file
       Netgear WNR1000,TP-LINK(TL-WDR5620),ASUS-LYRA, Xfinity XB3 ,Xfinity XB6 & Belkin AP'''

    '''Verify whether DUT is waked up before the nearest Beacon that does not exceed the specified listen interval
       time, Retrieving the buffered data by sending PS-POLL for every packet'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info('\n\n Time sleep ! Wait for 200 seconds......')
        time.sleep(100)

        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        wifi_sniffer.interfaces.capture.stop_capture()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        wlan_addr=ap_bssid,
                                                                                        filter_name='coex_enhanced_max_psp_34469')

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.
        # (for manual QA ref.)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_bssid,
                                                                                        association_id=association_id,
                                                                                        filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_assoc_id')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count']

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                  packet_filter2=packet_filter11)[
            'packet_count']

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_for_max_psp_95()
        result = frame_exchange_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                               'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> '
                'Null frame + pm bit 1 data packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference------------- ')
            sniffer_dict = frame_exchange_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert frame_exchange_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict), 'No sequence found for sniffer packets ' \
                               'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info(
                f'***** Validation of Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & Qos Data '
                f'packet time difference passed successfully *****')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_enhanced_max_psp_with_diff_traffic_c196700(wifi_sniffer, wifi_access_point, wifi_dut, net_perf_client,
                                                    protocol, sniffer_filter, sl_collections, wifi_client, request,
                                                    utf_constants):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 196700
    frame_exchange_obj = FilterPacket()
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Verify the functionality of DUT ,when ULP POWER SAVE MODE 2, FAST PSP and LISTEN INTERVAL based power save
     features are enabled when traffic is being run from different stations with different traffic streams'''

    '''Verify whether DUT is waked up before the nearest Beacon that does not exceed the specified listen interval
       time, Retrieving the buffered data by sending PS-POLL for every packet'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, data_transfer=False, net_perf_client=net_perf_client,
                          wifi_client=wifi_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # validate data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        wlan_addr=ap_bssid,
                                                                                        filter_name='coex_enhanced_max_psp_34469')

        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)[
            'packet_count']

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_for_max_psp_95()
        result = frame_exchange_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                               'Beacon(DTIM count 0)->PS-POLL->Qos data ' \
                                                                               'packet '

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference------------- ')
            sniffer_dict = frame_exchange_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert frame_exchange_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict), 'No sequence found for sniffer packets ' \
                               'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info(
                f'***** Validation of Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & Qos Data '
                f'packet time difference passed successfully *****')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_enhanced_max_psp_with_high_data_rate_c196703(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                                      sl_collections,
                                                      request, utf_constants):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 196703
    frame_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Verify whether DUT is able to wake up and receive Data based on listen interval with high data rates in power
      save 2 and ULP1, Listen interval based with Enhanced MAX PSP'''

    '''Verify whether DUT is waked up before the nearest Beacon that does not exceed the specified listen interval
       time, Retrieving the buffered data by sending PS-POLL for every packet'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info('\n\n Time sleep ! Wait for 200 seconds......')
        time.sleep(200)

        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        wifi_sniffer.interfaces.capture.stop_capture()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Validation for High data rates from DUT side
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name='radio_mcs_index_7')

        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        wlan_addr=ap_bssid,
                                                                                        filter_name='coex_enhanced_max_psp_34469')

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.
        # (for manual QA ref.)
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_bssid,
                                                                                        association_id=association_id,
                                                                                        filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_assoc_id')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find beacon with association-id and PS-poll packet with pm bit enable'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find  High data rates packets from DUT side'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter11)['packet_count'] \
            , 'Unable to find data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c)'

        logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence----------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_for_max_psp_95()
        result = frame_exchange_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                               'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference------------- ')
            sniffer_dict = frame_exchange_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert frame_exchange_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict), 'No sequence found for sniffer packets ' \
                               'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info(
                f'***** Validation of Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & Qos Data '
                f'packet time difference passed successfully *****')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_enhanced_max_psp_with_ulp_mode_dtim_c196704(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                                     sl_collections,
                                                     request, utf_constants):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 196704
    frame_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Verify whether DUT is able to wake up and receive Data based on DTIM beacon with power save mode2 and ULP mode &
       DTIM Based and Enhanced MAX PSP'''

    '''Verify whether DUT is waked up before the nearest Beacon that does not exceed the specified listen interval
       time, Retrieving the buffered data by sending PS-POLL for every packet'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info('\n\n Time sleep ! Wait for 200 seconds......')
        time.sleep(200)
        wifi_sniffer.interfaces.capture.stop_capture()

        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.
        # (for manual QA ref.)
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_bssid,
                                                                                        association_id=association_id,
                                                                                        filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_assoc_id')

        # Validation for High data rates from DUT side
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name='radio_mcs_index_7')

        # validate data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        wlan_addr=ap_bssid,
                                                                                        filter_name='coex_enhanced_max_psp_34469')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count']
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count']
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter11)[
            'packet_count']

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_for_max_psp_95()
        result = frame_exchange_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                               'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference---------------- ')
            sniffer_dict = frame_exchange_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert frame_exchange_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict), 'No sequence found for sniffer packets ' \
                               'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info(
                f'***** Validation of Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & Qos Data '
                f'packet time difference passed successfully *****')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_enhanced_max_psp_listen_interval_c196705(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                                  sl_collections,
                                                  request, utf_constants, wifi_client, net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 196705

    '''Verify Max/ Enhanced max PSP behavior with below scenariosend data for 1 min sleep, 1 min send data for
       5 min sleep, for 2min in listen interval bas'''

    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(5)

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client,
                          data_transfer=False)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # validate Null(0x24) with pm bit 1
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_enhanced_max_psp_dtim_c196706(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                       sl_collections, request, utf_constants, wifi_client, net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 196706

    '''Verify Max/ Enhanced max PSP behavior with below scenario - send data for 1 min → sleep 1 min → send data for
       5 min →sleep for 2min in DTIM based and PSP mode2'''

    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client,
                          data_transfer=False)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        da_addr=ap_bssid,
                                                                                        filter_name='power_mgmt_bit')

        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
