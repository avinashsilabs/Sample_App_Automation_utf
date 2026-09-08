import re
import time
from threading import Thread

import pytest
from retry import retry
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils import print_dict
from utf.utils.iperf.iperf_utils import ping, ping_qos
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.wifi.siwx3xx.tests.devices.siwx3xx import (
    Siwx3xxCoexMode,
    Siwx3xxConfigFeatureBitMap,
    Siwx3xxCustomFeatureBitMap,
    Siwx3xxExtCustomFeatureBitMap,
    Siwx3xxExtTCPIPFeatureBitMap,
    Siwx3xxFeatureBitMap,
    Siwx3xxOperatingMode,
    Siwx3xxTCPIPFeatureBitMap,
)
from utf_wiseconnect_3.wifi.siwx3xx.tests.sl_status import SLStatus

"""11ax aggregation and 802.11ax data-rate sniffer tests for SiWx3xx STA on 2.4 GHz.

    setup requirement:
        1. DUT (SiWx3xx SoC board)
        2. Raspberry PI4
        3. Access Point (Third Party AP's)
        4. Sniffer (NUC device)

    Authors: Venkatesulu Ekambaram
"""


def logger():
    return get_logger(__name__)


def wifi_dut_marker():
    """Generate wifi_dut marker for data-rate tests."""
    return pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
            "oper_mode": Siwx3xxOperatingMode.WiFiClient,
            "coex_mode": Siwx3xxCoexMode.WLAN | Siwx3xxCoexMode.BLE,
            "features": Siwx3xxFeatureBitMap.Default,
            "custom_features": Siwx3xxCustomFeatureBitMap.Default,
            "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
            | Siwx3xxExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0
            | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": 0,
            "ble_features": 0,
            "ble_custom_ext_features": 0,
        },
    )


class WifiJoin(ThreadBase):
    """Thread for 11ax aggregation join, traffic, and sniffer capture."""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, net_perf_client=None, wifi_client=None,
                 protocol=None, capture_filename=None, siwx3xx_collections=None, filter_name=None, test_case_no=None,
                 sniffer_filter=None, traffic=None, qos=None, power_save=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.capture_filename = capture_filename
        self.siwx3xx_collections = siwx3xx_collections
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

            self.dut_addr = self.siwx3xx_collections.join_to_wifi_network(
                self.wifi_dut,
                self.wifi_access_point,
                associated=self.wifi_dut.interfaces.wifi.associated,
                retry_count=3,
                power_save=False,
                ping_after_power_save=False,
            )
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


class SocketDataTransfer:
    """Socket-based data transfer helper for data-rate validation."""

    def __init__(self, wifi_dut=None, dut_ip=None, time_period=None, data=None, data_transfer=True,
                 wifi_access_point=None):
        self.wifi_dut = wifi_dut
        self.dut_ip = dut_ip
        self.time_period = time_period
        self.data = data
        self.data_transfer = data_transfer
        self.socket_id = None
        self.wifi_access_point = wifi_access_point

    def socket_data_transfer(self):
        if isinstance(self.wifi_dut.interfaces.wifi, SLWifiCLI):
            self.socket_id = self.wifi_dut.interfaces.wifi.socket(timeout=15)
            if isinstance(self.socket_id, int):
                logger().info(f"Socket open successfully : {self.socket_id}")
            else:
                logger().error(f"Unable to open socket id: {self.socket_id}")
                raise RuntimeError(self.socket_id)

            logger().info(f"Socket bind in DUT for socket-id: {self.socket_id}")
            self.wifi_dut.interfaces.wifi.bind(socket_fd=self.socket_id, device_ip=self.dut_ip, timeout=15)
            time.sleep(5)
            logger().info("Trying to connect with server")
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=self.socket_id, timeout=30)

            if self.data_transfer:
                sw = Stopwatch()
                while sw.elapsed_sec < self.time_period:
                    send_bytes = self.wifi_dut.interfaces.wifi.bsdSocketSend(
                        socket_fd=self.socket_id, data=self.data, timeout=120)
                    if isinstance(send_bytes, str):
                        logger().info(f"Send {send_bytes} bytes successfully")
                    else:
                        logger().info("Data transfer failed")

            time.sleep(5)
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.socket_id, timeout=30)

    @retry(Exception, delay=15, tries=5)
    def ping_to_dut(self, ping_count=10):
        status = ping(self.dut_ip, ping_count)
        assert status, "Failed to ping to DUT"
        return status


class WLanThread(ThreadBase):
    """Thread for data-rate sniffer capture and optional socket traffic."""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None, time_period=None,
                 ping_count=None, data_transfer=True, test_name=None, siwx3xx_collections=None, data_rates=None,
                 power_save=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.time_period = time_period
        self.data = 'Thisisfromclient'
        self.ping_count = ping_count
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.siwx3xx_collections = siwx3xx_collections
        self.test_name = test_name
        self.data_rates = data_rates
        self.power_save = power_save
        self.socket_obj = SocketDataTransfer(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            time_period=self.time_period,
            data=self.data,
        )

    def run(self):
        try:
            if self.test_case_no == 19628:
                self.wifi_dut.interfaces.wifi.set_transmit_rate(
                    rate_protocol="802.11g", data_rate="12Mbps", expected_status=SLStatus.SL_STATUS_OK)

            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            self.dut_addr = self.siwx3xx_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                associated=self.wifi_dut.interfaces.wifi.associated,
                retry_count=3,
                power_save=False,
                ping_after_power_save=False,
            )
            logger().info("DUT successfully connected with AP")
            time.sleep(10)
            if self.data_transfer:
                self.socket_obj.dut_ip = self.dut_addr['device_ip']
                self.socket_obj.socket_data_transfer()

            time.sleep(2)
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": Siwx3xxOperatingMode.WiFiClient,
            "coex_mode": Siwx3xxCoexMode.WLAN | Siwx3xxCoexMode.BLE,
            "features": Siwx3xxFeatureBitMap.Default,
            "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass | Siwx3xxTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
            "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default
            | Siwx3xxExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0
            | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
            "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
            | Siwx3xxExtTCPIPFeatureBitMap.WaitForSocketClose,
            "custom_features": Siwx3xxCustomFeatureBitMap.Default,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        },
    )
]


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0xc8', 6, "qos_voice_tx")])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148311')
def test_tcp_data_tx_with_VO_c148311(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, siwx3xx_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending TCP packets by aggregating in series of A-MPDU subframes when Access category of
    the TCP socket selected is AC-VO, when Aggregation feature is enabled in the DUT """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections, filter_name=filter_name,
                            sniffer_filter=sniffer_filter, traffic=traffic, qos=qos, test_case_no=148311, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0x80', 4, "qos_video_tx")])
@pytest.mark.legacy_deployed
@pytest.mark.WLAN_Dev_sanity_917
@pytest.mark.test_src_map_id('C148313')
def test_tcp_data_tx_with_VI_c148313(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, siwx3xx_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending TCP packets by aggregating in series of A-MPDU subframes when Access category of
    the TCP socket selected is AC-VI, when Aggregation feature is enabled in the DUT """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections, test_case_no=148313,
                            filter_name=filter_name, sniffer_filter=sniffer_filter, qos=qos, traffic=traffic, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0x20', 1, "qos_back_ground_tx")])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148314')
def test_tcp_data_tx_with_BK_c148314(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, siwx3xx_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending TCP packets by aggregating in series of A-MPDU subframes when Access category of
    the TCP socket selected is AC-BK, when Aggregation feature is enabled in the DUT. """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections, test_case_no=148314,
                            sniffer_filter=sniffer_filter, filter_name=filter_name, qos=qos, traffic=traffic, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0x00', 0, "qos_best_effort_tx")])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148315')
def test_tcp_data_tx_with_BE_c148315(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, siwx3xx_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending TCP packets by aggregating in series of A-MPDU subframes when Access category of
    the TCP socket selected is AC-BE, when Aggregation feature is enabled in the DUT. """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections, test_case_no=148315,
                            sniffer_filter=sniffer_filter, filter_name=filter_name, qos=qos, traffic=traffic, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0xc8', 6, "qos_voice_tx")])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148316')
def test_udp_data_tx_with_VO_c148316(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, siwx3xx_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending UDP packets by aggregating in series of A-MPDU subframes when Access category of
    the UDP socket selected is AC-VO, when Aggregation feature is enabled in the DUT """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections, filter_name=filter_name,
                            sniffer_filter=sniffer_filter, traffic=traffic, qos=qos, test_case_no=148316, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0x80', 4, "qos_video_tx")])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148317')
def test_udp_data_tx_with_VI_c148317(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, siwx3xx_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending UDP packets by aggregating in series of A-MPDU subframes when Access category of
    the UDP socket selected is AC-VI, when Aggregation feature is enabled in the DUT """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections, filter_name=filter_name,
                            sniffer_filter=sniffer_filter, traffic=traffic, qos=qos, test_case_no=148317, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()
    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0x00', 0, "qos_best_effort_tx")])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148318')
def test_udp_data_tx_with_BE_c148318(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, siwx3xx_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending UDP packets by aggregating in series of A-MPDU subframes when Access category of
    the UDP socket selected is AC-BE, when Aggregation feature is enabled in the DUT """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections, filter_name=filter_name,
                            sniffer_filter=sniffer_filter, traffic=traffic, qos=qos, test_case_no=148318, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()
    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos, filter_name", [('0x20', 1, "qos_back_ground_tx")])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148319')
def test_udp_data_tx_with_BK_c148319(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client,
                                     protocol, siwx3xx_collections, sniffer_filter, traffic, qos, filter_name):
    """ Verify whether DUT is sending UDP packets by aggregating in series of A-MPDU subframes when Access category of
    the UDP socket selected is AC-BK, when Aggregation feature is enabled in the DUT """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    try:
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections, filter_name=filter_name,
                            sniffer_filter=sniffer_filter, traffic=traffic, qos=qos, test_case_no=148319, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.sniffer_validation()
    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148320')
def test_udp_rx_check_block_ack_for_aggregated_frame_c148320(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                                             request, wifi_client, protocol, siwx3xx_collections,
                                                             sniffer_filter):
    """ Verify whether DUT is able to send Block ACK properly to all the aggregated frames received from AP with UDP """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    try:

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections,
                            sniffer_filter=sniffer_filter, test_case_no=148320, power_save=power_save)
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
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148323')
def test_dut_sending_mpdu_same_qos_cateqory_c148323(wifi_sniffer, wifi_access_point, wifi_dut, request, wifi_client,
                                                    siwx3xx_collections, sniffer_filter):
    """ To check whether DUT sending individual MPDU are of the same QoS access category """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    traffic = ['0x80', '0xc8']
    filter_list = [4, 6]

    try:
        packet_filter4 = '    Type/Subtype: QoS Data (0x0028)'
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections,
                            test_case_no=148323, sniffer_filter=sniffer_filter, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        tos6_thread = Thread(target=ping_qos, args=(wifi_obj.dut_addr['device_ip'], 60, "0xC8"))
        tos6_thread.start()
        status = ping_qos(wifi_obj.dut_addr['device_ip'], 60, qos_category='0x80')
        assert status == 1, "Ping failed for qos_category 0x80"
        tos6_thread.join()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        for qos_category in range(len(traffic)):
            filter_number = filter_list[qos_category]
            packet_filter3 = f'((wlan.sa == {wifi_obj.dut_addr["dut_mac_address"]}) || (wlan.ra == {wifi_obj.ap_mac_address})) and wlan.fc.type_subtype == 0x28 and (wlan.qos.priority == {filter_number})'
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
            ra_addr=wifi_obj.dut_addr['dut_mac_address'], sa_addr=wifi_obj.ap_mac_address,
            filter_name="11ax_aggre_block_ack")

        logger().info(f"***** Validating Association Request with HE Element ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Association Request with HE Element"

        logger().info(f"***** Validating Block ACK packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Block ACK packets"
    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148326')
def test_dut_receiving_mpdu_same_qos_cateqory_c148326(wifi_sniffer, wifi_access_point, wifi_dut, request, wifi_client,
                                                      siwx3xx_collections, sniffer_filter):
    """ To verify whether DUT is able to receive individual MPDUs are of the same QoS category """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    traffic_category_list = ['0xC8', '0x80']
    filter_list = [6, 4]
    try:
        packet_filter4 = '    Type/Subtype: QoS Data (0x0028)'
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections,
                            test_case_no=148326, sniffer_filter=sniffer_filter, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        tos6_thread = Thread(target=ping_qos, args=(wifi_obj.dut_addr['device_ip'], 60, "0xC8"))
        tos6_thread.start()
        status = ping_qos(wifi_obj.dut_addr['device_ip'], 60, qos_category='0x80')
        assert status == 1, "Ping failed for qos_category 0x80"
        tos6_thread.join()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        for qos_category in range(len(traffic_category_list)):
            filter_number = filter_list[qos_category]
            time.sleep(5)
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=wifi_obj.dut_addr['dut_mac_address'], da_addr=wifi_obj.ap_mac_address,
                filter_name="association_request_HE")
            packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=wifi_obj.dut_addr['dut_mac_address'], ra_addr=wifi_obj.ap_mac_address,
                filter_name="11ax_aggre_block_ack")
            packet_filter3 = (f'((wlan.da == {wifi_obj.dut_addr["dut_mac_address"]}) || '
                              f'(wlan.sa == {wifi_obj.ap_mac_address})) and (wlan.fc.type_subtype == 0x28) and '
                              f'(wlan.qos.priority == {filter_number})')

            logger().info(f"***** Validating Association Request with HE Element ******")
            snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']
            assert snif_pkt_count, "Unable to find Association Request with HE Element"

            logger().info(f"***** Validating Block ACK packets ******")
            snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
                'packet_count']
            assert snif_pkt_count, "Unable to find Block ACK packets"

            snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                                packet_filter2=packet_filter4)[
                'packet_count']
            assert snif_pkt_count, "Unable to find same qos access data packets"

            """This below method is used to validate TID and sequence numbers from DUT Tx Packet"""
            wifi_obj.sequence_number_tid_validation()
    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [('0x20', 1)])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148322')
def test_dut_send_mpdu_with_same_receiver_addr_c148322(
        wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client, protocol, siwx3xx_collections,
        sniffer_filter, traffic, qos):
    """ To verify whether DUT is sending individual MPDU within an A-MPDU are having the same receiver address """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    try:
        packet_filter4 = '    Type/Subtype: QoS Data (0x0028)'
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections, test_case_no=148322,
                            sniffer_filter=sniffer_filter, qos=qos, traffic=traffic, power_save=power_save)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        packet_filter3 = f'(wlan.sa == {wifi_obj.dut_addr["dut_mac_address"]}) and (wlan.ra == {wifi_obj.ap_mac_address}) and (wlan.qos.priority == 1)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter3, packet_filter2=packet_filter4)['packet_count']

        assert snif_pkt_count, "Unable to find qos access data packets with same receiver address"

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], da_addr=wifi_obj.ap_mac_address,
            filter_name="association_request_HE")

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ra_addr=wifi_obj.dut_addr['dut_mac_address'], sa_addr=wifi_obj.ap_mac_address,
            filter_name="11ax_aggre_block_ack")

        logger().info(f"***** Validating Association Request with HE Element ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Association Request with HE Element"

        logger().info(f"***** Validating Block ACK packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Block ACK packets"

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        """This below method is used to validate Receiver Address and Sequence Numbers and TID from DUT Tx Packet"""
        wifi_obj.receiver_address_sequence_number_validation()
    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

        """ ************************* The below Cases are Skipped and Marked as Manual ********************"""


@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [('0x00', 0)])
@pytest.mark.test_src_map_id('C148324')
def test_dut_receive_block_ack_after_ampdu_frames_c148324(
        wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client, protocol, siwx3xx_collections,
        sniffer_filter, traffic, qos):
    """ To check whether DUT is able to receive Block ACK properly after sending AMPDU frames """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    try:
        packet_filter4 = '    Type/Subtype: QoS Data (0x0028)'
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections, test_case_no=148324,
                            sniffer_filter=sniffer_filter, qos=qos, traffic=traffic, power_save=power_save)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        packet_filter3 = f'((wlan.sa == {wifi_obj.dut_addr["dut_mac_address"]}) || (wlan.ra == {wifi_obj.ap_mac_address})) and (wlan.qos.priority == 0)'
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
            ra_addr=wifi_obj.dut_addr['dut_mac_address'], sa_addr=wifi_obj.ap_mac_address,
            filter_name="11ax_aggre_block_ack")

        logger().info(f"***** Validating Association Request with HE Element ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Association Request with HE Element"

        logger().info(f"***** Validating Block ACK packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Block ACK packets"

        """This below method is used to validate TID and sequence numbers from DUT Tx Packet"""
        wifi_obj.sequence_number_tid_validation()

    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['net_init_client', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [('0x80', 4)])
@pytest.mark.test_src_map_id('C148325')
def test_dut_duration_id_carrying_same_value_c148325(
        wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, request, wifi_client, protocol, siwx3xx_collections,
        sniffer_filter, traffic, qos):
    """ To verify whether the Duration/ID field in the MAC headers of all MPDUs in an A-MPDU are carrying the same
    value or not """

    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    capture_filename = request.node.name
    try:
        packet_filter4 = '    Type/Subtype: QoS Data (0x0028)'
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, siwx3xx_collections=siwx3xx_collections, test_case_no=148325,
                            sniffer_filter=sniffer_filter, qos=qos, traffic=traffic, power_save=power_save)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        packet_filter3 = f'(wlan.sa == {wifi_obj.dut_addr["dut_mac_address"]}) and (wlan.ra == {wifi_obj.ap_mac_address}) and (wlan.qos.priority == 4)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                            packet_filter2=packet_filter4)[
            'packet_count']
        assert snif_pkt_count, "Unable to find qos access data packets with duration ID"

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], da_addr=wifi_obj.ap_mac_address,
            filter_name="association_request_HE")

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ra_addr=wifi_obj.dut_addr['dut_mac_address'], sa_addr=wifi_obj.ap_mac_address,
            filter_name="11ax_aggre_block_ack")

        logger().info(f"***** Validating Association Request with HE Element ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Association Request with HE Element"

        logger().info(f"***** Validating Block ACK packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Block ACK packets"

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        """This below method is used to validate duration ID and sequence numbers from DUT Tx Packet"""
        wifi_obj.duration_id_sequence_number_validation()

    except Exception as Ex:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


# ---------------------------------------------------------------------------
# 802.11ax data-rate sniffer tests
# ---------------------------------------------------------------------------


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19622')
def test_wifi_sdk_siwx3xx_mgmt_data_rates_c19622(
        wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request, sniffer_filter, siwx3xx_collections):
    """Verify management packet data rates at 1 Mbps."""
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name
    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        time_period=time_period,
        ping_count=ping_count,
        test_name=test_name,
        siwx3xx_collections=siwx3xx_collections,
        data_transfer=False,
        power_save=power_save,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info(f"\n\n\n DUT MAC Address = {wlan_obj.dut_addr['dut_mac_address']}\n\n")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name='mgmt_data_rates_1_mbps')

        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Probe Request & Authentication Req & Association Req & EAPOL(2&4) and Deauth mgmt packets'
    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19624')
def test_wifi_sdk_siwx3xx_data_rates_for_data_packet_c19624(
        wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request, sniffer_filter, siwx3xx_collections):
    """Verify data/null/QoS packet data rates at 1 Mbps."""
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name
    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        time_period=time_period,
        ping_count=ping_count,
        test_name=test_name,
        siwx3xx_collections=siwx3xx_collections,
        power_save=power_save,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name='mgmt_data_rates_data_null_Qos_1mbps')

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Data/Null/Qos packets data rates'
    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": { "wifi":{ "count": 1, "stack_len": 2048 }} ,
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLAN | Siwx3xxCoexMode.BLE,
        "features": Siwx3xxFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default | Siwx3xxExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Siwx3xxCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
@pytest.mark.test_src_map_id('C19630')
def test_wifi_sdk_data_rates_with_diff_rssi_values_c19630(wifi_sniffer, wifi_access_point, wifi_dut, rf_attenuator,
                                                          utf_constants, request, sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name
    set_rssi = 0
    packet_filter6 = '    Data Rate:'

    '''Verify data rate functionality of STA DUT using AUTO RATE as data rate with AP OPEN mode'''
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    scan_results = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_point.interfaces.wifi.ssid)
    logger().info(f'\n\n{scan_results[0]}\n')
    my_str = str(scan_results[0])
    current_rssi = abs(int(my_str.strip('()').split(' ')[5]))
    logger().info(f'Current RSSI = {current_rssi}')
    logger().info(f'Make RSSI -35 for ideal condition')
    if current_rssi < 35:
        set_rssi = 35 - current_rssi
    elif current_rssi > 35:
        set_rssi = current_rssi - 35
    elif current_rssi == 35:
        set_rssi = 35

    logger().info(f'SET RSSI value = {set_rssi}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                          ping_count=ping_count, test_name=test_name, test_case_no=19622)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.
            interfaces.wifi.channel,
            filter_name='probe_request')
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            da_addr=ap_bssid,
            filter_name='association_request')
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_bssid,
                                                                                        da_addr=wlan_obj.dut_addr[
                                                                                            'dut_mac_address'],
                                                                                        filter_name='association_response')
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            da_addr=ap_bssid,
            filter_name='power_mgmt_bit')
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'],
            ra_addr=ap_bssid,
            filter_name='data_packets')

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast probe request packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find Association req packets'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find Association response packets'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find Power save mode with pmt bit 1'

        if connect_status is False:
            logger().info("Unable to connect with Server")
            assert connect_status
        else:
            sw = Stopwatch()
            db_value = 10
            att_channel = 1
            attenuation_data_rates_dict = dict()

            file_name = 'attenuation_' + str(db_value)
            logger().info('***** Set the attenuator *****')
            # ideal_rssi = set_rssi + current_rssi
            # set_db_value = int(ideal_rssi) + db_value
            ideal_rssi = 10
            set_db_value = int(ideal_rssi) + db_value
            logger().info(f'\n\n Set the ideal RSSI = {ideal_rssi}\n')
            wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel, ideal_rssi)

            while sw.elapsed_sec < time_period:

                time.sleep(10)

                wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
                wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
                logger().info(f'current time = {sw.elapsed_sec}, end time = {time_period}')
                send_response = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data=data)
                logger().info(f'SEND-RESPONSE = {send_response}')

                logger().info(f'\n\n set_db_value = {set_db_value}\n')
                wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel, set_db_value)
                time.sleep(10)
                sw1 = Stopwatch()
                while sw1.elapsed_sec < 30:
                    logger().info(f'\n\n current time = {sw.elapsed_sec}\n')
                    send_response = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data=data)
                    logger().info(f'\n\n SEND-RESPONSE = {send_response}\n')
                wifi_sniffer.interfaces.capture.stop_capture()

                assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5,
                                                                          packet_filter2=packet_filter6)['packet_count'], \
                    'Unable to find data packets'

                attenuation_data_rates_dict[eval('set_db_value')] = tcp_socket_obj.verify_data_rates()
                logger().info(f'Attenuation and Data Rates value = {attenuation_data_rates_dict}')
                set_db_value = set_db_value + 10

            logger().info(f'Attenuation and Data Rates value = {attenuation_data_rates_dict}')
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19631')
def test_wifi_sdk_siwx3xx_data_rates_eapol_c19631(
        wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request, sniffer_filter, siwx3xx_collections):
    """Verify EAPOL packet data rates at 1 Mbps with auto rate."""
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name
    power_save = False
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    wlan_obj = WLanThread(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_sniffer=wifi_sniffer,
        time_period=time_period,
        ping_count=ping_count,
        test_name=test_name,
        test_case_no=19628,
        siwx3xx_collections=siwx3xx_collections,
        power_save=power_save,
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name='mgmt_data_rates_eapol_1mbps')

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find packets for EAPOL packets for 1 Mbps data rates'
    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
