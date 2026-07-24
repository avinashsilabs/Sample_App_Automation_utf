from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils import print_dict
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, ping_qos
from utf.utils.thread_base import ThreadBase
import re
from threading import Thread
from utf.utf_config import UtfConfig

"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : gnbax
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Send traffic of TCP/UDP/TX/RX
    
    setup requirement:
        1. soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC-device)

    Author: Benazeer K 

"""


def logger():
    return get_logger(__name__)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, net_perf_client=None, wifi_client=None,
                 protocol=None, capture_filename=None, zephyr_wifi_collections=None, filter_name=None,
                 test_case_no=None,
                 sniffer_filter=None, traffic=None, qos=None, power_save=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.capture_filename = capture_filename
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.filter_name = filter_name
        self.ap_mac_address = None
        self.host_ip = None
        self.test_case_no = test_case_no
        self.sniffer_filter = sniffer_filter
        self.traffic = traffic
        self.qos = qos
        self.dut_addr = None
        self.iperf_throughput = None
        self.power_save = power_save

    def print_throughput(self):
        if self.iperf_throughput is not None:
            print_dict("##     ", self.iperf_throughput)

    def run(self):
        try:
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}")

            self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                              associated=self.wifi_dut.interfaces.wifi.associated,
                                                                              retry_count=3, power_save=self.power_save,
                                                                              ping_after_power_save=True)
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"******** AP MAC ADDRESS is {self.ap_mac_address} *******")
            self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"***** Host IP Address is {self.host_ip} ******")

            if self.test_case_no not in [148312, 148320, 148323, 148326]:
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol, tos_value=self.traffic)
                logger().info(
                    f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}, "
                    f"tos_value: {self.traffic}")
                logger().info(f"***** starting iperf ******")
                self.net_perf_client.interfaces.net_perf.start()
                logger().info(f"***** send traffic ******")

            if self.test_case_no == 148311 or self.test_case_no == 148313 or self.test_case_no == 148314 or self.test_case_no == 148315 or self.test_case_no == 148324 or self.test_case_no == 148325 or self.test_case_no == 148322:
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=self.host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    size=1460, ttl=30, throughput_type=1, qos=self.qos)

            if self.test_case_no == 148316 or self.test_case_no == 148317 or self.test_case_no == 148318 or self.test_case_no == 148319:
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                                    local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=self.host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    size=1460, ttl=30, throughput_type=2, qos=self.qos)

            if self.test_case_no not in [148312, 148320, 148323, 148326]:
                logger().info(f"***** get and print throughput ******")
                self.iperf_throughput = self.net_perf_client.interfaces.net_perf.process_output()
                assert self.iperf_throughput, "failed to get throughput..."
                self.print_throughput()
                logger().info("data transfer is successful")
                time.sleep(5)
                logger().info("Dut going to leave the AP")
                self.wifi_dut.interfaces.wifi.leave()
                self.wifi_sniffer.interfaces.capture.stop_capture()
                logger().info("Stop Sniffer finally")

        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")

    def sniffer_validation(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="association_request_HE")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], filter_name=self.filter_name)

        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=self.dut_addr['dut_mac_address'], filter_name="wmm_aggre_cts")

        packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=self.dut_addr['dut_mac_address'], filter_name="radiotap_HE_data")

        logger().info(f"***** Validating Association Request with HE Element ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Association Request with HE Element"

        logger().info(f"***** Validating qos category packets ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "qos category packets are not captured in the sniffer"

        logger().info(f"***** Validating Block ACK packets ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Block ACK packets"

        logger().info(f"***** Validating HE information in the radio tap header ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count']
        assert snif_pkt_count, "Unable to HE information in the radio tap header"
        self.zephyr_wifi_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer,
                                                             self.dut_addr['dut_mac_address'], self.ap_mac_address,
                                                             self.sniffer_filter, power_save=self.power_save)

    def sequence_number_tid_validation(self):
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        content = filter_file.read()
        sequence_number = re.findall(r"(....\s=\sSequence\snumber:\s\d+)", content)
        content_tid = re.findall(r"(TID:\s\d+)", content)
        logger().info(f' ********* Calculating length of {len(content_tid)} and {len(sequence_number)}***********')

        """The below code lines is used to print TID and sequence number from DUT Tx Packet"""
        if self.test_case_no in [148323, 148326]:
            for i in range(len(sequence_number)):
                logger().info(f' ********* {sequence_number[i]} and {content_tid[i]}***********')

    def duration_id_sequence_number_validation(self):
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        content = filter_file.read()
        content_duration = re.findall(r"(Duration:\s\d+\smicroseconds)", content)
        sequence_number = re.findall(r"(....\s=\sSequence\snumber:\s\d+)", content)
        logger().info(f' ********* Calculating length of {len(content_duration)} and {len(sequence_number)}***********')

        """The below code lines is used to print duration id and sequence number from DUT Tx Packet"""
        for i in range(min(len(content_duration), len(sequence_number))):
            logger().info(f' ********* {content_duration[i]} and {sequence_number[i]} ***********')

    def receiver_address_sequence_number_validation(self):
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        content = filter_file.read()
        receiver_address = re.findall(r"(\s\s\s\sReceiver\saddress:\s[\w:]+)", content)
        sequence_number = re.findall(r"(....\s=\sSequence\snumber:\s\d+)", content)
        tid = re.findall(r"(TID:\s\d+)", content)
        logger().info(
            f' ********* Calculating length of AP mac address : {len(receiver_address)} and length of Qos Packet Sequence Number : {len(sequence_number)} and length of TID : {len(tid)} ***********')

        """The below code lines is used to print receiver_address and sequence number and TID from DUT Tx Packet"""
        for i in range(len(sequence_number)):
            logger().info(f' ********* {receiver_address[i]} and {sequence_number[i]} and {tid[i]} ***********')


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0xc8', 6, "qos_voice_tx")])
@pytest.mark.test_src_map_id('C148311')
def test_wifi_sta_tcp_tx_c148311(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                 protocol, zephyr_wifi_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending TCP TX Traffic """

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            filter_name=filter_name,
                            sniffer_filter=sniffer_filter, traffic=traffic, qos=0, power_save=False,
                            test_case_no=148311)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C148320')
def test_wifi_sta_tcp_rx_c148320(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                 protocol, zephyr_wifi_collections, sniffer_filter):
    """ Verify whether DUT is sending UDP RX Traffic"""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            power_save=False)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        time.sleep(2)
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=wifi_obj.dut_addr['device_ip'],
                                                        protocol=protocol)
        logger().info(f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}, ")

        def start_client():
            time.sleep(3)
            logger().info(f"***** Connect to server  ******")
            net_perf_client.interfaces.net_perf.start()

        client_thread1 = Thread(target=start_client, args=(), )
        client_thread1.start()

        logger().info(f"***** Start listening ******")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=wifi_obj.dut_addr['device_ip'], remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1470, ttl=30, throughput_type=3, qos=0)
        logger().info("data transfer is successful")
        time.sleep(2)
        logger().info("Dut going to leave the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0xc8', 6, "qos_voice_tx")])
@pytest.mark.test_src_map_id('C148316')
def test_wifi_sta_udp_tx_c148316(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                 protocol, zephyr_wifi_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending UDP TX Traffic """

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            filter_name=filter_name,
                            sniffer_filter=sniffer_filter, traffic=traffic, qos=0, test_case_no=148316,
                            power_save=False)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.test_src_map_id('C148320')
def test_wifi_sta_udp_rx_c148320(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                 protocol, zephyr_wifi_collections, sniffer_filter):
    """ Verify whether DUT is sending UDP RX Traffic"""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            sniffer_filter=sniffer_filter, test_case_no=148320, power_save=False)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        net_perf_client.interfaces.net_perf.init_client(host_ip=wifi_obj.host_ip,
                                                        device_ip=wifi_obj.dut_addr['device_ip'],
                                                        protocol=protocol, bandwidth="1M")
        logger().info(f"Host IP: {wifi_obj.host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}")
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** send traffic  ******")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=wifi_obj.dut_addr['device_ip'], remote_ip=wifi_obj.host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1470, ttl=30, throughput_type=4)
        logger().info("data transfer is successful")
        time.sleep(2)
        logger().info("Dut going to leave the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
