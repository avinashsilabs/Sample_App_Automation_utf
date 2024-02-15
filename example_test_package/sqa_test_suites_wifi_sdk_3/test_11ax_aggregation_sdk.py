from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, ping_qos
from utf.utils.thread_base import ThreadBase
import re

"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        6. Enable the power save mode in DUT
        7. Stop the sniffer
        8. Analyzing all sniffer capture packets and find the different Qos access category packets 
        
    traffic category for Iperf category
        1. wlan.qos.priority == 0  Best Effort
        2. wlan.qos.priority == 1  Background
        3. wlan.qos.priority == 4  Video
        4. wlan.qos.priority == 6  Voice

    setup requirement:
        1. soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: Saurabh Sharma

"""


def logger():
    return get_logger(__name__)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, net_perf_client=None, wifi_client=None,
                 protocol=None, capture_filename=None, sl_collections=None, filter_name=None, test_case_no=None,
                 sniffer_filter=None, traffic=None, qos=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.capture_filename = capture_filename
        self.sl_collections = sl_collections
        self.filter_name = filter_name
        self.ap_mac_address = None
        self.host_ip = None
        self.test_case_no = test_case_no
        self.sniffer_filter = sniffer_filter
        self.traffic = traffic
        self.qos = qos
        self.dut_addr = None
        self.iperf_throughput = None

    def print_throughput(self):
        if self.iperf_throughput is not None:
            print_dict("##     ", self.iperf_throughput)

    def run(self):
        try:
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}")

            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)
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

            if self.test_case_no == 148311 or self.test_case_no == 148313 or self.test_case_no == 148314 or self.test_case_no == 148315 or self.test_case_no == 148324 or self.test_case_no == 148325 or self.test_case_no == 148322 :
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

    def sequence_number_tid_validation(self):
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        content = filter_file.read()
        sequence_number = re.findall(r"(....\s=\sSequence\snumber:\s\d+)", content)
        content_tid = re.findall(r"(TID:\s\d+)", content)
        logger().info(f' ********* Calculating length of {len(content_tid)} and {len(sequence_number)}***********')

        """The below code lines is used to print TID and sequence number from DUT Tx Packet"""
        if self.test_case_no == 148326:
            for i in range(len(sequence_number)):
                logger().info(f' ********* {sequence_number[i]} and {content_tid[i]}***********')

    def duration_id_sequence_number_validation(self):
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        content = filter_file.read()
        content_duration = re.findall(r"(Duration:\s\d+\smicroseconds)", content)
        sequence_number = re.findall(r"(....\s=\sSequence\snumber:\s\d+)", content)
        logger().info(f' ********* Calculating length of {len(content_duration)} and {len(sequence_number)}***********')

        """The below code lines is used to print duration id and sequence number from DUT Tx Packet"""
        # for i in range(len(sequence_number)):
        #     logger().info(f' ********* {content_duration[i]} and {sequence_number[i]} ***********')

    def receiver_address_sequence_number_validation(self):
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        content = filter_file.read()
        receiver_address = re.findall(r"(\s\s\s\sReceiver\saddress:\s[\w:]+)", content)
        sequence_number = re.findall(r"(....\s=\sSequence\snumber:\s\d+)", content)
        logger().info(f' ********* Calculating length of {len(receiver_address)} and {len(sequence_number)}***********')

        """The below code lines is used to print receiver_address and sequence number from DUT Tx Packet"""
        # for i in range(len(sequence_number)):
        #     logger().info(f' ********* {receiver_address[i]} and {sequence_number[i]} ***********')


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "custom_features": Si91xCustomFeatureBitMap.Default,
        }
    )
]


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0xc8', 6, "qos_voice_tx")])
def test_tcp_data_tx_with_VO_c148311(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, sl_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending TCP packets by aggregating in series of A-MPDU subframes when Access category of
    the TCP socket selected is AC-VO, when Aggregation feature is enabled in the DUT """

    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections, filter_name=filter_name,
                            sniffer_filter=sniffer_filter, traffic=traffic, qos=qos, test_case_no=148311)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0x80', 4, "qos_video_tx")])
def test_tcp_data_tx_with_VI_c148313(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, sl_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending TCP packets by aggregating in series of A-MPDU subframes when Access category of
    the TCP socket selected is AC-VI, when Aggregation feature is enabled in the DUT """

    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections, test_case_no=148313,
                            filter_name=filter_name, sniffer_filter=sniffer_filter, qos=qos, traffic=traffic)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0x20', 1, "qos_back_ground_tx")])
def test_tcp_data_tx_with_BK_c148314(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, sl_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending TCP packets by aggregating in series of A-MPDU subframes when Access category of
    the TCP socket selected is AC-BK, when Aggregation feature is enabled in the DUT. """

    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections, test_case_no=148314,
                            sniffer_filter=sniffer_filter, filter_name=filter_name, qos=qos, traffic=traffic)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0x00', 0, "qos_best_effort_tx")])
def test_tcp_data_tx_with_BE_c148315(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, sl_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending TCP packets by aggregating in series of A-MPDU subframes when Access category of
    the TCP socket selected is AC-BE, when Aggregation feature is enabled in the DUT. """

    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections, test_case_no=148315,
                            sniffer_filter=sniffer_filter, filter_name=filter_name, qos=qos, traffic=traffic)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
def test_ping_from_remote_to_dut_c148312(wifi_sniffer, wifi_access_point, wifi_dut, request, wifi_client,
                                         sl_collections, sniffer_filter):
    """ Verify whether DUT is able to send SMPDU when we do only single packet from remote PC """

    capture_filename = request.node.name
    try:
        ping_count = 20
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            test_case_no=148312, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        logger().info(f"***** Initiate ping from remote PC to DUT IP ******")
        status = ping(wifi_obj.dut_addr['device_ip'], ping_count)
        assert status is True, "DUT is not responding to ping request from remote PC"
        logger().info(f"************* Ping is successful *************")

        logger().info("Dut going to leave the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], da_addr=wifi_obj.ap_mac_address,
            filter_name="association_request_HE")

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name="icmp_ack_ampdu_disable")

        logger().info(f"***** Validating Association Request with HE Element ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Association Request with HE Element"

        logger().info(f"***** Validating  AP is sending the Ack for each ping reply from DUT ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "Unable to find AP is sending the Ack for each ping reply from DUT"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0xc8', 6, "qos_voice_tx")])
def test_udp_data_tx_with_VO_c148316(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, sl_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending UDP packets by aggregating in series of A-MPDU subframes when Access category of
    the UDP socket selected is AC-VO, when Aggregation feature is enabled in the DUT """

    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections, filter_name=filter_name,
                            sniffer_filter=sniffer_filter, traffic=traffic, qos=qos, test_case_no=148316)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0x80', 4, "qos_video_tx")])
def test_udp_data_tx_with_VI_c148317(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, sl_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending UDP packets by aggregating in series of A-MPDU subframes when Access category of
    the UDP socket selected is AC-VI, when Aggregation feature is enabled in the DUT """

    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections, filter_name=filter_name,
                            sniffer_filter=sniffer_filter, traffic=traffic, qos=qos, test_case_no=148317)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0x00', 0, "qos_best_effort_tx")])
def test_udp_data_tx_with_BE_c148318(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, sl_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending UDP packets by aggregating in series of A-MPDU subframes when Access category of
    the UDP socket selected is AC-BE, when Aggregation feature is enabled in the DUT """

    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections, filter_name=filter_name,
                            sniffer_filter=sniffer_filter, traffic=traffic, qos=qos, test_case_no=148318)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0x20', 1, "qos_back_ground_tx")])
def test_udp_data_tx_with_BK_c148319(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, sl_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending UDP packets by aggregating in series of A-MPDU subframes when Access category of
    the UDP socket selected is AC-BK, when Aggregation feature is enabled in the DUT """

    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections, filter_name=filter_name,
                            sniffer_filter=sniffer_filter, traffic=traffic, qos=qos, test_case_no=148319)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_udp_rx_check_block_ack_for_aggregated_frame_c148320(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                                             request, wifi_client, protocol, sl_collections,
                                                             sniffer_filter):
    """ Verify whether DUT is able to send Block ACK properly to all the aggregated frames received from AP with UDP """

    capture_filename = request.node.name
    try:

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections,
                            sniffer_filter=sniffer_filter, test_case_no=148320)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        net_perf_client.interfaces.net_perf.init_client(host_ip=wifi_obj.host_ip,
                                                        device_ip=wifi_obj.dut_addr['device_ip'],
                                                        protocol=protocol)
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

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], da_addr=wifi_obj.ap_mac_address,
            filter_name="association_request_HE")

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name="wmm_aggre_cts")

        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name="radiotap_HE_data")

        logger().info(f"***** Validating Association Request with HE Element ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Association Request with HE Element"

        logger().info(f"***** Validating Block ACK packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Block ACK packets"

        logger().info(f"***** Validating HE information in the radio tap header ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to HE information in the radio tap header"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_dut_sending_mpdu_same_qos_cateqory_c148323(
        wifi_sniffer, wifi_access_point, wifi_dut, request, wifi_client, sl_collections, sniffer_filter, protocol,
        net_perf_client):
    """ To check whether DUT sending individual MPDU are of the same QoS access category """

    capture_filename = request.node.name
    traffic = ['0x80', '0xc8']
    filter_list = [4, 6]
    filter_number = ''

    try:
        packet_filter4 = '    Type/Subtype: QoS Data (0x0028)'
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            test_case_no=148323, sniffer_filter=sniffer_filter, protocol=protocol, traffic=traffic,
                            net_perf_client=net_perf_client)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        for qos_category in range(len(traffic)):
            net_perf_client.interfaces.net_perf.init_server(host_ip=wifi_obj.host_ip,
                                                            device_ip=wifi_obj.dut_addr['device_ip'],
                                                            protocol=protocol, tos_value=traffic[qos_category])
            logger().info(
                f"Host IP: {wifi_obj.host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}, "
                f"tos_value: {traffic[qos_category]}")
            logger().info(f"***** starting iperf ******")
            net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** send traffic  ******")
            wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                           local_port=net_perf_client.interfaces.net_perf.server_port,
                                           local_ip=wifi_obj.dut_addr['device_ip'], remote_ip=wifi_obj.host_ip,
                                           remote_port=net_perf_client.interfaces.net_perf.server_port,
                                           size=1460, ttl=30, throughput_type=1, qos=filter_list[qos_category])
            logger().info(f"***** get and print throughput ******")
            iperf_throughput = net_perf_client.interfaces.net_perf.process_output()
            assert iperf_throughput, "failed to get throughput..."
            wifi_obj.print_throughput()
            logger().info("data transfer is successful")
            time.sleep(5)
            filter_number = filter_list[qos_category]

            packet_filter3 = f'((wlan.sa == {wifi_obj.dut_addr["dut_mac_address"]}) || (wlan.ra == {wifi_obj.ap_mac_address})) and tcp and (wlan.qos.priority == {filter_number})'

            snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                                packet_filter2=packet_filter4)['packet_count']
            assert snif_pkt_count, "Unable to find same qos access data packets"

            """This below method is used to validate duration ID and sequence numbers from DUT Tx Packet"""
            wifi_obj.sequence_number_tid_validation()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], da_addr=wifi_obj.ap_mac_address,
            filter_name="association_request_HE")

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ra_addr=wifi_obj.dut_addr['dut_mac_address'], sa_addr=wifi_obj.ap_mac_address, filter_name="11ax_aggre_block_ack")

        logger().info(f"***** Validating Association Request with HE Element ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
        assert snif_pkt_count, "Unable to find Association Request with HE Element"

        logger().info(f"***** Validating Block ACK packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count']
        assert snif_pkt_count, "Unable to find Block ACK packets"

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open'})
def test_dut_receiving_mpdu_same_qos_cateqory_c148326(
        wifi_sniffer, wifi_access_point, wifi_dut, request, wifi_client, sl_collections, sniffer_filter):
    """ To verify whether DUT is able to receive individual MPDUs are of the same QoS category """

    capture_filename = request.node.name
    traffic_category_list = ['0xC8', '0x80']
    filter_list = [6, 4]
    filter_number = ''
    try:
        packet_filter4 = '    Type/Subtype: QoS Data (0x0028)'
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            test_case_no=148326, sniffer_filter=sniffer_filter)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        for qos_category in range(len(traffic_category_list)):
            status = ping_qos(wifi_obj.dut_addr['device_ip'], 30, qos_category=traffic_category_list[qos_category])
            assert status == 1, "Ping failed"
            filter_number = filter_list[qos_category]
            time.sleep(5)

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=wifi_obj.dut_addr['dut_mac_address'], da_addr=wifi_obj.ap_mac_address,
                filter_name="association_request_HE")

            packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=wifi_obj.dut_addr['dut_mac_address'], ra_addr=wifi_obj.ap_mac_address, filter_name="11ax_aggre_block_ack")

            packet_filter3 = f'((wlan.sa == {wifi_obj.dut_addr["dut_mac_address"]}) || (wlan.ra == {wifi_obj.ap_mac_address})) and icmp and (wlan.qos.priority == {filter_number})'

            logger().info(f"***** Validating Association Request with HE Element ******")
            snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            assert snif_pkt_count, "Unable to find Association Request with HE Element"

            logger().info(f"***** Validating Block ACK packets ******")
            snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count']
            assert snif_pkt_count, "Unable to find Block ACK packets"

            snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                                packet_filter2=packet_filter4)['packet_count']
            assert snif_pkt_count, "Unable to find same qos access data packets"

            """This below method is used to validate TID and sequence numbers from DUT Tx Packet"""
            wifi_obj.sequence_number_tid_validation()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [('0x00', 0)])
def test_dut_receive_block_ack_after_ampdu_frames_c148324(
        wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client, protocol, sl_collections,
        sniffer_filter, traffic, qos):
    """ To check whether DUT is able to receive Block ACK properly after sending AMPDU frames """

    capture_filename = request.node.name
    try:
        packet_filter4 = '    Type/Subtype: QoS Data (0x0028)'
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections, test_case_no=148324,
                            sniffer_filter=sniffer_filter, qos=qos, traffic=traffic)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        packet_filter3 = f'((wlan.sa == {wifi_obj.dut_addr["dut_mac_address"]}) || (wlan.ra == {wifi_obj.ap_mac_address})) and tcp and (wlan.qos.priority == 0)'

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                            packet_filter2=packet_filter4)[
            'packet_count']
        assert snif_pkt_count, "Unable to find same qos access data packets"

        """This below method is used to validate duration ID and sequence numbers from DUT Tx Packet"""
        wifi_obj.sequence_number_tid_validation()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], da_addr=wifi_obj.ap_mac_address,
            filter_name="association_request_HE")

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ra_addr=wifi_obj.dut_addr['dut_mac_address'], sa_addr=wifi_obj.ap_mac_address, filter_name="11ax_aggre_block_ack")

        logger().info(f"***** Validating Association Request with HE Element ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
        assert snif_pkt_count, "Unable to find Association Request with HE Element"

        logger().info(f"***** Validating Block ACK packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count']
        assert snif_pkt_count, "Unable to find Block ACK packets"

        """This below method is used to validate TID and sequence numbers from DUT Tx Packet"""
        wifi_obj.sequence_number_tid_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [('0x80', 4)])
def test_dut_duration_id_carrying_same_value_c148325(
        wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client, protocol, sl_collections,
        sniffer_filter, traffic, qos):
    """ To verify whether the Duration/ID field in the MAC headers of all MPDUs in an A-MPDU are carrying the same
    value or not """

    capture_filename = request.node.name
    try:
        packet_filter4 = '    Type/Subtype: QoS Data (0x0028)'
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections, test_case_no=148325,
                            sniffer_filter=sniffer_filter, qos=qos, traffic=traffic)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        packet_filter3 = f'(wlan.sa == {wifi_obj.dut_addr["dut_mac_address"]}) and (wlan.ra == {wifi_obj.ap_mac_address}) and tcp and (wlan.qos.priority == 4)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                            packet_filter2=packet_filter4)[
            'packet_count']
        assert snif_pkt_count, "Unable to find qos access data packets with duration ID"

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], da_addr=wifi_obj.ap_mac_address,
            filter_name="association_request_HE")

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ra_addr=wifi_obj.dut_addr['dut_mac_address'], sa_addr=wifi_obj.ap_mac_address, filter_name="11ax_aggre_block_ack")

        logger().info(f"***** Validating Association Request with HE Element ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
        assert snif_pkt_count, "Unable to find Association Request with HE Element"

        logger().info(f"***** Validating Block ACK packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count']
        assert snif_pkt_count, "Unable to find Block ACK packets"

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        """This below method is used to validate duration ID and sequence numbers from DUT Tx Packet"""
        wifi_obj.duration_id_sequence_number_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [('0x20', 1)])
def test_dut_send_mpdu_with_same_receiver_addr_c148322(
        wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client, protocol, sl_collections,
        sniffer_filter, traffic, qos):
    """ To verify whether DUT is sending individual MPDU within an A-MPDU are having the same receiver address """

    capture_filename = request.node.name
    try:
        packet_filter4 = '    Type/Subtype: QoS Data (0x0028)'
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections, test_case_no=148322,
                            sniffer_filter=sniffer_filter, qos=qos, traffic=traffic)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        packet_filter3 = f'(wlan.sa == {wifi_obj.dut_addr["dut_mac_address"]}) || (wlan.ra == {wifi_obj.ap_mac_address}) and tcp and (wlan.qos.priority == 1)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter3, packet_filter2=packet_filter4)['packet_count']

        assert snif_pkt_count, "Unable to find qos access data packets with same receiver address"

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], da_addr=wifi_obj.ap_mac_address,
            filter_name="association_request_HE")

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ra_addr=wifi_obj.dut_addr['dut_mac_address'], sa_addr=wifi_obj.ap_mac_address, filter_name="11ax_aggre_block_ack")

        logger().info(f"***** Validating Association Request with HE Element ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
        assert snif_pkt_count, "Unable to find Association Request with HE Element"

        logger().info(f"***** Validating Block ACK packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count']
        assert snif_pkt_count, "Unable to find Block ACK packets"

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        """This below method is used to validate duration ID and sequence numbers from DUT Tx Packet"""
        wifi_obj.receiver_address_sequence_number_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
