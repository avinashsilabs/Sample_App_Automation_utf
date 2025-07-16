import pytest
import time
import re
from datetime import datetime, date
import random
import string
from threading import Thread
from utf.interfaces.socket.fixtures import remote_socket
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xOperatingMode,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xJoinFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xRegionCode,
)
from collections import Counter
from utf_wiseconnect_3.tests.interfaces.sl_collections import SLCollections
from utf.utils.thread_base import ThreadBase
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from utf.utils.stopwatch import Stopwatch
from utf.utils.time_measurer import TimeMeasurer
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.sl_status import SLStatus

"""
Author: Achal Raghav

Description:
This file contains test cases for validating the behavior of the Wi-Fi SDK under various scenarios, 
including Channel Switch Announcements (CSA) and HTTP Over-The-Air Firmware (OTAF) upgrades. 
The tests ensure the Device Under Test (DUT) adheres to expected functionality during channel switches, 
data transfers, and firmware upgrades.

Test Cases Overview:
- C776228: CSA with RX data transfer (WPA2)
- C776229: CSA with TX data transfer (WPA2) 
- C776230: CSA with minimum switch count (1 beacon)
- C776231: CSA with maximum switch count (255 beacons)
- C776232: CSA when AP switched to unsupported region (Europe channel 13)
- C776233: CSA with OTAF upgrade in parallel (HTTP firmware upgrade)
- C776234: CSA with AWS shadow updates (SSL/TLS)
- C776235: CSA with WPA3 personal security (PMF enabled)
- C776236: CSA with WPA3 enterprise security (EAP-TLS)
- C776237: Frequent CSA changes (rapid channel switching)
- C776238: CSA immediate disconnect with WPA2 enterprise
- C776239: CSA with MBSSID enabled AP (multiple SSIDs)
- C776240: CSA with switch mode (data transmission allowed)
- C776241: CSA with quiet mode (no data transmission)
- C779609: CSA with instant background scan
- C779701: CSA with background scan during RX data transfer (SKIPPED)

Requirements:
- Python 3.x
- Pytest framework
- Wi-Fi DUT with CSA and HTTP OTAF capabilities
- Access point and sniffer setup
- UTF test framework and dependencies
"""


def logger():
    return get_logger(__name__)


class WLANCSAThread(ThreadBase):
    """
    A thread class to handle WLAN Channel Switch Announcement (CSA) operations.

    Attributes:
        wifi_dut: The Wi-Fi device under test.
        wifi_access_point: The Wi-Fi access point.
        wifi_sniffer: The Wi-Fi sniffer for capturing packets.
        sl_collections: SLCollections instance for managing Wi-Fi operations.
        remote_socket_factory: Factory for creating remote sockets.
        request: The pytest request object.
        dut_addr: The address of the device under test.
        testcase_id: The ID of the test case being executed.
        transfer_type: The type of data transfer (e.g., TX or RX).
        channel: The channel to switch to during CSA.
        beacon_count: The number of beacons to send during CSA.
    """

    def __init__(
        self,
        wifi_dut=None,
        wifi_access_point=None,
        wifi_sniffer=None,
        sl_collections=None,
        remote_socket_factory=None,
        request=None,
        dut_addr=None,
        testcase_id=None,
        transfer_type=None,
        http_server=None,
        utf_constants=None,
        sniffer_filter=None,
        channel=11,
        beacon_count=4,
        sniff_in_csa_channel=False,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.remote_socket_factory = remote_socket_factory
        self.request = request
        self.dut_addr = dut_addr
        self.channel = channel
        self.testcase_id = testcase_id
        self.transfer_type = transfer_type
        self.beacon_count = beacon_count
        self.http_server = http_server
        self.utf_constants = utf_constants
        self.sniffer_filter = sniffer_filter
        self.sniff_in_csa_channel = sniff_in_csa_channel

    @staticmethod
    def channel_switch_info_element():
        """
        Reads and parses the Channel Switch Announcement (CSA) information
        from a file.

        Returns:
            dict: A dictionary containing CSA information such as
                  'Channel Switch Mode', 'New Channel Number', and
                  'Channel Switch Count'.
        """
        csa_dict_info = dict()
        with open("./reports/filter2_file.txt", "r") as file:
            data = file.read()
            patterns = [
                r"Channel Switch Mode:\s+(\d+)",
                r"New Channel Number:\s+(\d+)",
                r"Channel Switch Count:\s+(\d+)",
                r"Epoch Time:\s+(\d+\.\d+)",
            ]
            for pattern in patterns:
                match = re.search(pattern, data)
                if match:
                    csa_dict_info[pattern.split(":")[0]] = match.group(1)
        return csa_dict_info

    def csa_sniffer_validation(self):
        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.wifi_access_point.interfaces.wifi.bssid,
                filter_name="channel_switch_announcement",
            )
        )
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1,
            packet_filter2="       Tag: Channel Switch Announcement",
        )["packet_count"]
        csa_dict_info = WLANCSAThread.channel_switch_info_element()
        logger().info(f"\n The CSA Info Element is: {csa_dict_info} \n")

        assert (
            snif_pkt_count
        ), "\n Channel Switch Announcement Packet Present in Sniffer Capture \n"
        assert (
            int(csa_dict_info["New Channel Number"]) == self.channel
        ), f" **** Switched Channel doesn't match the Set Channel **** "
        return csa_dict_info

    def rejoin_request_validation(self):
        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_addr["dut_mac_address"],
                da_addr=self.wifi_access_point.interfaces.wifi.bssid,
                filter_name="csa_rejoin_packet",
            )
        )
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1,
        )["packet_count"]
        assert (
            int(snif_pkt_count) == 0
        ), f"\n Association Request Shouldn't be Present BTW DUT and AP in the Switched Channel: {self.channel} \n"

    def find_ssid_list_from_dut_scan(self, scan_type=False):
        # collect all ssid from DUT scan list
        ssid_list = []
        if scan_type:
            self.scan_list = self.wifi_dut.interfaces.wifi.scan(
                channel=0,
                ssid=None,
                scan_bitmap_2_4=0,
                scan_type=2,
                bg_scan_periodicity=10,
            )
            logger().info(
                f"\n\n *** Start to collect all available ssid in DUT scan list ***\n\n"
            )
        else:
            self.scan_list = self.wifi_dut.interfaces.wifi.scan()
            logger().info(
                f"\n\n *** Start to collect all available ssid in DUT scan list ***\n\n"
            )

        for i in range(0, len(self.scan_list)):
            ssid_list.append(self.scan_list[i].ssid)
        return ssid_list

    def verfiy_T_and_NT_based_mbssid_in_dut_list(self, scan_type=False):
        # Validation for T and NT based MBSSID in DUT scan list & sniffer capture
        packet_filter2 = "                    SSID:"
        ssid_list = self.find_ssid_list_from_dut_scan(scan_type=scan_type)
        # Check the ssid list from DUT scan list
        assert len(ssid_list) > 0, "DUT scan list is empty"
        return ssid_list

    def get_firmware_status(self):
        self.wifi_dut.interfaces.wifi.reset()
        time.sleep(30)
        logger().info("Initialising DUT after the reset....")
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        self.wifi_dut.interfaces.wifi.init(load_certificate=False)
        self.wifi_dut.interfaces.wifi.initialize_thread()
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_after_upgrade = self.wifi_dut.interfaces.wifi.version()
        self.wifi_dut.interfaces.wifi.inited = False
        time.sleep(5)
        return fw_after_upgrade

    def aws_cloud_connectivity(self):
        self.client_id = self.request.node.name + "_client"
        self.topic = "topic_" + self.request.node.name
        logger().info(
            f"\n The Client_ID is : {self.client_id} and Topic is : {self.topic}"
        )
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        self.wifi_dut.interfaces.wifi.aws_iot_shadow_init(
            hostname="a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com"
        )
        logger().info(f"\n ....Initiating Connection to AWS Cloud.... \n")
        self.wifi_dut.interfaces.wifi.aws_iot_shadow_connect(timeout=120)
        self.wifi_dut.interfaces.wifi.aws_iot_shadow_register_delta()

    def aws_shadow_update(self):
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            logger().info(f"\n\n Getting Shadow Update \n\n ")
            self.wifi_dut.interfaces.wifi.aws_iot_shadow_yield()
            self.wifi_dut.interfaces.wifi.aws_iot_shadow_init_json_document()
            self.wifi_dut.interfaces.wifi.aws_iot_shadow_add_reported()
            self.wifi_dut.interfaces.wifi.aws_iot_finalize_json_document()
            self.wifi_dut.interfaces.wifi.aws_iot_shadow_update()

    def run(self):
        """
        Executes the thread's main logic for handling CSA operations.
        Depending on the test case ID, it performs data transfer (TX or RX)
        and initiates CSA on the access point.
        """
        if not self.sniff_in_csa_channel:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=(self.wifi_access_point.interfaces.wifi.channel)
            )
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=self.request.node.name
            )
        if self.testcase_id == 776235:
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
            )
        if self.testcase_id in [776236, 776238]:
            self.dut_addr = self.sl_collections.join_to_eap_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                power_save=False,
                security=(
                    "wpa3_enterprise"
                    if self.testcase_id == 776236
                    else "wpa2_enterprise"
                ),
                channel=self.wifi_access_point.interfaces.wifi.channel,
            )
        else:
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                associated=self.wifi_dut.interfaces.wifi.associated,
                power_save=False,
                channel=self.wifi_access_point.interfaces.wifi.channel,
            )
        if self.sniff_in_csa_channel:
            self.wifi_sniffer.interfaces.capture.configure_interface(self.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(self.request.node.name)
        if self.testcase_id == 776228:
            data_transfer_obj = DataTransfer(
                wifi_dut=self.wifi_dut,
                remote_socket_factory=self.remote_socket_factory,
                dut_addr=self.dut_addr,
                transfer_type="RX",
            )
            data_transfer_obj.start_remote_server()
            rx_thread = Thread(target=data_transfer_obj.receive_tcp_data)
            csa_thread = Thread(
                target=self.wifi_access_point.interfaces.wifi.enable_disable_csa,
                args=(self.channel, self.beacon_count, True),
            )
            rx_thread.start()
            logger().info(f" <---- Initiating CSA ----> ")
            time.sleep(5)
            csa_thread.start()
            rx_thread.join()
        if self.testcase_id == 776229:
            data_transfer_obj = DataTransfer(
                wifi_dut=self.wifi_dut,
                remote_socket_factory=self.remote_socket_factory,
                dut_addr=self.dut_addr,
                transfer_type="TX",
            )
            data_transfer_obj.start_remote_server()
            tx_thread = Thread(target=data_transfer_obj.transmit_tcp_data)
            csa_thread = Thread(
                target=self.wifi_access_point.interfaces.wifi.enable_disable_csa,
                args=(self.channel, self.beacon_count, True),
            )
            tx_thread.start()
            logger().info(f" <---- Initiating CSA ----> ")
            time.sleep(5)
            csa_thread.start()
            tx_thread.join()

        if self.testcase_id == 776230:
            data_transfer_obj = DataTransfer(
                wifi_dut=self.wifi_dut,
                remote_socket_factory=self.remote_socket_factory,
                dut_addr=self.dut_addr,
                transfer_type="RX",
            )
            data_transfer_obj.start_remote_server()
            tx_thread = Thread(target=data_transfer_obj.receive_tcp_data)
            csa_thread = Thread(
                target=self.wifi_access_point.interfaces.wifi.enable_disable_csa,
                args=(self.channel, self.beacon_count, False),
            )
            tx_thread.start()
            logger().info(f" <---- Initiating CSA ----> ")
            time.sleep(5)
            csa_thread.start()
            tx_thread.join()

        if self.testcase_id == 776231:
            data_transfer_obj = DataTransfer(
                wifi_dut=self.wifi_dut,
                remote_socket_factory=self.remote_socket_factory,
                dut_addr=self.dut_addr,
                transfer_type="RX",
            )
            data_transfer_obj.start_remote_server()
            tx_thread = Thread(target=data_transfer_obj.receive_tcp_data)
            csa_thread = Thread(
                target=self.wifi_access_point.interfaces.wifi.enable_disable_csa,
                args=(self.channel, self.beacon_count, False),
            )
            tx_thread.start()
            logger().info(f" <---- Initiating CSA ----> ")
            time.sleep(5)
            csa_thread.start()
            tx_thread.join()

        if self.testcase_id == 776232:
            data_transfer_obj = DataTransfer(
                wifi_dut=self.wifi_dut,
                remote_socket_factory=self.remote_socket_factory,
                dut_addr=self.dut_addr,
                transfer_type="RX",
            )
            data_transfer_obj.start_remote_server()
            tx_thread = Thread(target=data_transfer_obj.receive_tcp_data)
            csa_thread = Thread(
                target=self.wifi_access_point.interfaces.wifi.enable_disable_csa,
                args=(self.channel, self.beacon_count, False),
            )
            tx_thread.start()
            logger().info(f" <---- Initiating CSA ----> ")
            time.sleep(5)
            csa_thread.start()
            tx_thread.join()

        if self.testcase_id == 776233:
            logger().info("\n Checking HTTP Server Status \n")
            server_stat = self.http_server.interfaces.http.started
            assert server_stat == True, " ---- Server is InActive ---- "
            host_ip = self.http_server.interfaces.http.hostname_or_ip_address
            logger().info(f" **** SERVER IP: {host_ip} **** ")

            logger().info("\n Checking Ping to Server \n")
            status = ping(host_ip, 10)
            assert status == 1, " ---- Ping to Server Failed ---- "

            fw_before_upgrade = self.wifi_dut.interfaces.wifi.version()
            logger().info(
                f" ***** FW Version before Upgrade: {fw_before_upgrade} *****"
            )
            otaf_thread = Thread(
                target=self.wifi_dut.interfaces.wifi.firmware_upgrade,
                args=(0, host_ip, 80, self.utf_constants.get("rps_filename"), host_ip),
            )
            csa_thread = Thread(
                target=self.wifi_access_point.interfaces.wifi.enable_disable_csa,
                args=(self.channel, self.beacon_count, False),
            )
            logger().info("\n Starting HTTP OTAF Upgrade \n")
            otaf_thread.start()
            logger().info(f" <---- Initiating CSA ----> ")
            time.sleep(15)
            csa_thread.start()
            otaf_thread.join()
            self.wifi_dut.interfaces.wifi.leave()
            fw_after_upgrade = self.get_firmware_status()
            time.sleep(2)
            logger().info(
                f"\n\n *** Firmware Version before OTAF: {fw_before_upgrade}"
                f" Firmware Version after OTAF: {fw_after_upgrade}"
            )
            assert (
                fw_before_upgrade != fw_after_upgrade
            ), f"\n\n **** Firmware Version not Matching **** \n\n"
            logger().info(f"\n\n ***** Firmware Upgrade Successful ***** \n\n")
        if self.testcase_id == 776234:
            self.aws_cloud_connectivity()
            aws_thread = Thread(target=self.aws_shadow_update)
            csa_thread = Thread(
                target=self.wifi_access_point.interfaces.wifi.enable_disable_csa,
                args=(self.channel, self.beacon_count, True),
            )
            aws_thread.start()
            logger().info(f" <---- Initiating CSA ----> ")
            time.sleep(2)
            csa_thread.start()
            aws_thread.join()
            logger().info(f"\n....Disconnecting from AWS Cloud....\n")
            self.wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
        if self.testcase_id == 776235:
            data_transfer_obj = DataTransfer(
                wifi_dut=self.wifi_dut,
                remote_socket_factory=self.remote_socket_factory,
                dut_addr=self.dut_addr,
                transfer_type="TX",
            )
            data_transfer_obj.start_remote_server()
            tx_thread = Thread(target=data_transfer_obj.transmit_tcp_data)
            csa_thread = Thread(
                target=self.wifi_access_point.interfaces.wifi.enable_disable_csa,
                args=(self.channel, self.beacon_count, True),
            )
            tx_thread.start()
            logger().info(f" <---- Initiating CSA ----> ")
            time.sleep(5)
            csa_thread.start()
            tx_thread.join()
        if self.testcase_id == 776236:
            data_transfer_obj = DataTransfer(
                wifi_dut=self.wifi_dut,
                remote_socket_factory=self.remote_socket_factory,
                dut_addr=self.dut_addr,
                transfer_type="RX",
            )
            data_transfer_obj.start_remote_server()
            rx_thread = Thread(target=data_transfer_obj.receive_tcp_data)
            csa_thread = Thread(
                target=self.wifi_access_point.interfaces.wifi.enable_disable_csa,
                args=(self.channel, self.beacon_count, True),
            )
            rx_thread.start()
            logger().info(f" <---- Initiating CSA ----> ")
            time.sleep(5)
            csa_thread.start()
            rx_thread.join()
        if self.testcase_id == 776239:
            data_transfer_obj = DataTransfer(
                wifi_dut=self.wifi_dut,
                remote_socket_factory=self.remote_socket_factory,
                dut_addr=self.dut_addr,
                transfer_type="RX",
            )
            data_transfer_obj.start_remote_server()
            tx_thread = Thread(target=data_transfer_obj.receive_tcp_data)
            csa_thread = Thread(
                target=self.wifi_access_point.interfaces.wifi.enable_disable_csa,
                args=(self.channel, self.beacon_count, True),
            )
            tx_thread.start()
            logger().info(f" <---- Initiating CSA ----> ")
            time.sleep(5)
            csa_thread.start()
            tx_thread.join()
        if self.testcase_id == 776240:
            data_transfer_obj = DataTransfer(
                wifi_dut=self.wifi_dut,
                remote_socket_factory=self.remote_socket_factory,
                dut_addr=self.dut_addr,
                transfer_type="TX",
            )
            data_transfer_obj.start_remote_server()
            tx_thread = Thread(target=data_transfer_obj.transmit_tcp_data)
            csa_thread = Thread(
                target=self.wifi_access_point.interfaces.wifi.enable_disable_csa,
                args=(self.channel, self.beacon_count, False),
            )
            tx_thread.start()
            logger().info(f" <---- Initiating CSA ----> ")
            time.sleep(5)
            csa_thread.start()
            tx_thread.join()
        if self.testcase_id == 776241:
            data_transfer_obj = DataTransfer(
                wifi_dut=self.wifi_dut,
                remote_socket_factory=self.remote_socket_factory,
                dut_addr=self.dut_addr,
                transfer_type="TX",
            )
            data_transfer_obj.start_remote_server()
            tx_thread = Thread(target=data_transfer_obj.transmit_tcp_data)
            csa_thread = Thread(
                target=self.wifi_access_point.interfaces.wifi.enable_disable_csa,
                args=(self.channel, self.beacon_count, True),
            )
            tx_thread.start()
            logger().info(f" <---- Initiating CSA ----> ")
            time.sleep(5)
            csa_thread.start()
            tx_thread.join()


class DataTransfer:
    def __init__(
        self,
        wifi_dut=None,
        remote_socket_factory=None,
        dut_addr=None,
        transfer_type="TX",
    ):
        self.remote_socket_factory = remote_socket_factory
        self.dut_addr = dut_addr
        self.wifi_dut = wifi_dut
        self.local_port = 5001
        self.socket_id = None
        self.client_socket = None
        self.transfer_type = transfer_type

    def start_remote_server(self):
        self.client_socket = (
            self.remote_socket_factory.interfaces.socket.create_socket()
        )
        self.socket_id = (
            self.wifi_dut.interfaces.wifi.Asyncsocket(
                domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP"
            )
            if self.transfer_type == "RX"
            else self.wifi_dut.interfaces.wifi.socket(
                domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP"
            )
        )
        logger().info(f"Socket open successfully : {self.socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {self.socket_id} which is expected"
        )
        if self.transfer_type == "TX":
            self.client_socket.start_server(port=self.local_port)
        self.wifi_dut.interfaces.wifi.bind(
            socket_fd=self.socket_id,
            device_ip=self.dut_addr["device_ip"],
            server_port=self.local_port,
            timeout=5,
            asynch=1 if self.transfer_type == "RX" else 0,
        )
        if self.transfer_type == "RX":
            self.wifi_dut.interfaces.wifi.listen(
                socket_fd=self.socket_id, backlog=1, asynch=1
            )
            ThreadBase.call_functions_simultaneously(
                [
                    (self.wifi_dut.interfaces.wifi.bsdSocketAccept, self.socket_id, 1),
                    (
                        self.client_socket.connect_client_tcp,
                        self.dut_addr["device_ip"],
                        self.local_port,
                    ),
                ],
                timeout=10,
            )
        else:
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                socket_fd=self.socket_id,
                server_ip=self.client_socket.hostname_or_ip_address(),
                server_port=self.local_port,
            )

    def transmit_tcp_data(self):
        sw = Stopwatch()
        logger().info(f"\n Starting the TCP TX data Transfer \n")
        while sw.elapsed_sec < 60:
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )
            self.wifi_dut.interfaces.wifi.bsdSocketSend(
                socket_fd=self.socket_id, data=sent_data, higher_data_len=0
            )
            self.client_socket.set_recv_timeout(socket_type=0)
            received_data = self.client_socket.recv_data_tcp(len(sent_data))
            logger().info(
                f"\n###################### Received TCP Data: {received_data} ######################\n"
            )
            assert (
                sent_data == received_data
            ), f"Data mismatch in sent and received data"

    def receive_tcp_data(self):
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            tx_buffer = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=50)
            )
            buffer_length = len(tx_buffer)
            logger().info(
                f"Remote peer sending data over socket {self.socket_id} and data:{tx_buffer}"
            )
            self.client_socket.send_data_tcp(tx_buffer, use_server_socket=False)
            self.wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(
                socket_fd=self.socket_id + 1
            )
            logger().info(
                f"###################### Buffer Data  {buffer_rx}  ######################"
            )
            logger().info(
                f"###################### Buffer Data Length  {buffer_length}  ######################"
            )
            assert tx_buffer == buffer_rx, (
                f"buffer length sent by remote peer and received on the socket id "
                f"{self.socket_id} opened in the DUT is not matched"
            )
            logger().info("Data sent by remote peer and received on DUT is matching")

        self.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=self.socket_id)
        logger().info("Successfully closed opened socket in the DUT")


def wifi_dut_fixture(
    ca_cert=None, client_cert=None, client_key=None, pmf_enable=False, region=False
):
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": (
            Si91xExtCustomFeatureBitMap.Default
            | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
            | Si91xExtCustomFeatureBitMap.IEEE802_11W
            if pmf_enable
            else 0
        ),
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
        | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
    if region:
        config["region"] = 1
        config["region_code"] = Si91xRegionCode.US
    if ca_cert:
        config["ca_cert"] = ca_cert
    if client_cert:
        config["client_cert"] = client_cert
    if client_key:
        config["client_key"] = client_key
    return pytest.mark.config("wifi_dut", wifi=config)


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [8])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_with_rx_data_transfer_c776228(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
):
    try:
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776228,
            sniffer_filter=sniffer_filter,
            sniff_in_csa_channel=True,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        csa_thread_object.rejoin_request_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [9])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_with_tx_data_transfer_c776229(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
):
    try:
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            sniff_in_csa_channel=True,
            testcase_id=776229,
            sniffer_filter=sniffer_filter,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        csa_thread_object.rejoin_request_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [1])
@pytest.mark.parametrize("beacon_count", [1])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_with_min_switch_count_c776230(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
    beacon_count,
):
    try:
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776230,
            beacon_count=beacon_count,
            sniffer_filter=sniffer_filter,
            sniff_in_csa_channel=True,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        csa_thread_object.rejoin_request_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [7])
@pytest.mark.parametrize("beacon_count", [255])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_with_max_switch_count_c776231(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
    beacon_count,
):
    try:
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776231,
            beacon_count=beacon_count,
            sniffer_filter=sniffer_filter,
            sniff_in_csa_channel=True,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        csa_thread_object.rejoin_request_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture(region=True)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point", wifi={"channel": 6, "security": "WPA2", "region": "Europe"}
)
@pytest.mark.parametrize("channel", [13])
@pytest.mark.parametrize("beacon_count", [4])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_when_ap_switched_to_unsupported_region_c776232(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
    beacon_count,
):
    try:
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776232,
            beacon_count=beacon_count,
            sniffer_filter=sniffer_filter,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        csa_dict_info = csa_thread_object.csa_sniffer_validation()
        # Validate the Association Request sent by DUT after CSA
        logger().info(
            f"\n Validating the Probe Request sent to establish a Connection after switching to Unsupported Region Channel: {channel} after Epoch Time: {csa_dict_info['Epoch Time']}\n"
        )
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=csa_thread_object.dut_addr["dut_mac_address"],
            filter_name="probe_request",
        )
        assoc_request_pkt = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter2
            + f" and frame.time_epoch >= {csa_dict_info['Epoch Time']}",
        )["packet_count"]
        assert (
            assoc_request_pkt
        ), f"No Probe Request to Reconnect to Access Point from DUT"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1
        | Si91xFeatureBitMap.WPSSupportDisabled
        | Si91xFeatureBitMap.Aggregation
        | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.HTTPClient
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
        | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF
        | Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [4])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_csa_with_otaf_upgrade_in_parallel_c776233(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
    http_server,
    utf_constants,
):
    try:
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776233,
            http_server=http_server,
            utf_constants=utf_constants,
            sniffer_filter=sniffer_filter,
            sniff_in_csa_channel=True,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        csa_thread_object.rejoin_request_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.SSL
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.DNSClient
        | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.RsaKeyWith4096Support
        | Si91xExtCustomFeatureBitMap.SslCertWith4096Support
        | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": [
            "start_field.pem",
            "SL_NET_SIGNING_CERTIFICATE",
            "SL_NET_TLS_SERVER_CREDENTIAL_START",
        ],
        "client_cert": [
            "client-certificate.crt",
            "SL_NET_CERTIFICATE",
            "SL_NET_TLS_CLIENT_CREDENTIAL_START",
        ],
        "client_key": [
            "private-key.key",
            "SL_NET_PRIVATE_KEY",
            "SL_NET_TLS_CLIENT_CREDENTIAL_START",
        ],
    },
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [2])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_with_aws_shadow_updates_C776234(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
):
    try:
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776234,
            sniffer_filter=sniffer_filter,
            sniff_in_csa_channel=True,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        csa_thread_object.rejoin_request_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_fixture(pmf_enable=True)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA3"})
@pytest.mark.parametrize("channel", [5])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_with_wpa3_personal_security_c776235(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    sniffer_filter,
    channel,
    remote_socket_factory,
):
    try:
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776235,
            beacon_count=10,
            sniffer_filter=sniffer_filter,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        commit_message = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=csa_thread_object.dut_addr["dut_mac_address"],
            filter_name="wpa3_confirm_commit_message",
        )
        logger().info(f"\n\n\n Sniffer Filter = {commit_message}\n\n")

        eapol_messages = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=csa_thread_object.dut_addr["dut_mac_address"],
            filter_name="wpa3_4_way_handshake_message",
        )
        logger().info(f"\n\n\n Sniffer Filter = {eapol_messages}\n\n")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=commit_message
        )["packet_count"], "\n Unable to find Commit and Confirm Packets \n"

        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=eapol_messages
        )["packet_count"], "\n Unable to find Association & EAPOL packets. \n"
        csa_thread_object.csa_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket_factory.interfaces.socket.close_all()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled
        | Si91xFeatureBitMap.PSKSecurity
        | Si91xFeatureBitMap.Aggregation
        | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
        | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": [
            "wifi-user.pem",
            "SL_NET_CERTIFICATE",
            "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID",
        ],
    },
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"channel": 1, "security": "WPA2Enterprise", "passphrase": "12345678"},
)
@pytest.mark.parametrize("channel", [2])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "clear_certs"]
)
def test_wifi_sdk_csa_with_wpa3_enterprise_security_c776236(
    wifi_dut,
    wifi_access_point,
    radius_server,
    wifi_sniffer,
    sl_collections,
    request,
    sniffer_filter,
    channel,
    remote_socket_factory,
):
    try:

        logger().info(
            "Since WPA3-Enterprise is not supported on third-party Asus APs, "
            "as per input from the QA team, WPA2-Enterprise with PMF was configured "
            "on the third-party side, and WPA3-Enterprise with PMF was enabled on the DUT."
        )
        wifi_access_point.interfaces.wifi.config["protected_management_frame"] = (
            "Required"
        )
        wifi_access_point.interfaces.wifi.start_ap()
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776236,
            beacon_count=4,
            sniffer_filter=sniffer_filter,
            sniff_in_csa_channel=True,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        csa_thread_object.rejoin_request_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "open"})
@pytest.mark.parametrize("channel_sequence", [[8, 1, 6, 2, 3, 7, 11, 10, 4, 5, 9]])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_frequent_csa_changes_c776237(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel_sequence,
):
    try:
        initial_capture_channel = wifi_access_point.interfaces.wifi.channel
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel_sequence[0],
            testcase_id=776237,
            sniffer_filter=sniffer_filter,
        )
        data_transfer_obj = DataTransfer(
            wifi_dut=wifi_dut,
            remote_socket_factory=remote_socket_factory,
            transfer_type="RX",
        )
        csa_thread_object.dut_addr = sl_collections.join_to_wifi_network(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            associated=wifi_dut.interfaces.wifi.associated,
            power_save=False,
        )
        data_transfer_obj.dut_addr = csa_thread_object.dut_addr
        data_transfer_obj.start_remote_server()
        rx_thread = Thread(target=data_transfer_obj.receive_tcp_data)
        rx_thread.start()

        # Step 7: Trigger CSA in rapid succession
        for ch in range(0, len(channel_sequence)):
            capture_channel = channel_sequence[ch]
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=capture_channel,
            )
            wifi_sniffer.interfaces.capture.start_capture(
                capture_file=f"CSA_CAPTURE_IN_{capture_channel}.pcap"
            )
            logger().info(
                f" <---- Initiating CSA to channel {channel_sequence[ch]} from Channel {initial_capture_channel} ----> "
            )
            wifi_access_point.interfaces.wifi.enable_disable_csa(
                channel=channel_sequence[ch], beacon_count=10, enable=True
            )
            time.sleep(5)
            initial_capture_channel = channel_sequence[ch]
            # Step 8: Validate sniffer for CSA packets and correct channel
            csa_thread_object.rejoin_request_validation()
            wifi_sniffer.interfaces.capture.stop_capture()
        rx_thread.join()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled
        | Si91xFeatureBitMap.PSKSecurity
        | Si91xFeatureBitMap.Aggregation
        | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
        | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": [
            "wifi-user.pem",
            "SL_NET_CERTIFICATE",
            "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID",
        ],
    },
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"channel": 1, "security": "WPA2Enterprise", "passphrase": "12345678"},
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_immediate_disconnect_wpa2_enterprise_c776238(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    radius_server,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
):
    try:
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776238,
            beacon_count=4,
            sniff_in_csa_channel=True,
            sniffer_filter=sniffer_filter,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        data_transfer_obj = DataTransfer(
            wifi_dut=wifi_dut,
            remote_socket_factory=remote_socket_factory,
            dut_addr=csa_thread_object.dut_addr,
            transfer_type="RX",
        )
        data_transfer_obj.start_remote_server()
        rx_thread = Thread(target=data_transfer_obj.receive_tcp_data)
        rx_thread.start()
        time.sleep(2)
        csa_thread = Thread(
            target=wifi_access_point.interfaces.wifi.enable_disable_csa,
            args=(channel, 4, True),
        )
        csa_thread.start()
        csa_thread.join()
        wifi_dut.interfaces.wifi.leave()
        rx_thread.join(timeout=5)

        csa_thread_object.rejoin_request_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "MBSSID_AP",
        "channel": 3,
        "standard": "gnbax",
        "security": "WPA2",
        "passphrase": "123456789",
        "guest_networks": [
            {
                "index": "1",
                "ssid": "MBSSID_TEST_1",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "2",
                "ssid": "MBSSID_TEST_2",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
            {
                "index": "3",
                "ssid": "MBSSID_TEST_3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 3,
            },
        ],
    },
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("channel", [13])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_with_mbssid_enabled_ap_c776239(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    sniffer_filter,
    channel,
    remote_socket_factory,
):
    try:
        beacon_count = 10
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776239,
            beacon_count=4,
            sniffer_filter=sniffer_filter,
        )
        vap_list = csa_thread_object.verfiy_T_and_NT_based_mbssid_in_dut_list()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file="CSA_CAPTURE_IN_13.pcap"
        )
        logger().info(f"The VAP List is: {vap_list}")
        time.sleep(2)
        wifi_dut.interfaces.wifi.join(
            ssid=vap_list[1],
            passphrase=wifi_access_point.interfaces.wifi.guest_networks[1][
                "passphrase"
            ],
            security=wifi_access_point.interfaces.wifi.guest_networks[1][
                "security"
            ].name.lower(),
        )

        dut_addr = sl_collections.join_to_wifi_network(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            associated=False,
            ping_after_power_save=False,
            skip_scan=True,
            skip_connect=True,
            retry_count=3,
            power_save=False,
        )
        csa_thread_object.dut_addr = dut_addr
        data_transfer_obj = DataTransfer(
            wifi_dut=wifi_dut,
            remote_socket_factory=remote_socket_factory,
            dut_addr=dut_addr,
            transfer_type="RX",
        )
        data_transfer_obj.start_remote_server()
        rx_thread = Thread(target=data_transfer_obj.receive_tcp_data)
        csa_thread = Thread(
            target=wifi_access_point.interfaces.wifi.enable_disable_csa,
            args=(channel, beacon_count, False),
        )
        rx_thread.start()
        logger().info(f" <---- Initiating CSA ----> ")
        time.sleep(5)
        csa_thread.start()
        rx_thread.join()
        csa_thread_object.rejoin_request_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [5])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_with_switch_mode_c776240(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
):
    try:
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776240,
            sniffer_filter=sniffer_filter,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        csa_dict_info = csa_thread_object.csa_sniffer_validation()
        # For Transmission Mode  Data Frames could be Transmitted BTW STA and AP Till CSA Happens
        data_packet_count = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=f"wlan.fc.type == 2 and wlan.sa == {csa_thread_object.dut_addr['dut_mac_address']} and"
            f" frame.time_epoch >= {csa_dict_info['Epoch Time']}"
        )["find_packet_num"]
        assert (
            int(data_packet_count) > 0
        ), f"\n Data Frames aren't Exchanged BTW STA and AP During CSA in Transmission Mode \n"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "OPEN"})
@pytest.mark.parametrize("channel", [4])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_with_quiet_mode_c776241(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
):
    try:
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776241,
            beacon_count=15,
            sniffer_filter=sniffer_filter,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        csa_dict_info = csa_thread_object.csa_sniffer_validation()
        # For Quite Mode No Data Frames should be Transmitted BTW STA and AP Till CSA Happens
        data_packet_count = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=f"wlan.fc.type == 2 and wlan.sa == {csa_thread_object.dut_addr['dut_mac_address']} and"
            f" frame.time_epoch >= {csa_dict_info['Epoch Time']}"
        )["packet_count"]
        assert (
            data_packet_count == False
        ), f"\n Data Frames Exchanged BTW STA and AP During CSA in Quite Mode which isn't Expected \n"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_with_instant_bgscan_c779609(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
):
    try:
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=779609,
            sniffer_filter=sniffer_filter,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        """ Enabling BG scan """
        wifi_dut.interfaces.wifi.set_advanced_scan_configuration(
            adv_active_channel_time=15,
            adv_passive_channel_time=20,
            adv_enable_instant_scan=1,
            adv_trigger_level=-100,
            adv_trigger_level_change=50,
        )
        logger().info("\n *** Enable BgScan *** \n")
        wifi_access_point.interfaces.wifi.enable_disable_csa(
            channel, beacon_count=20, enable=True
        )
        wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)

        csa_dict_info = csa_thread_object.csa_sniffer_validation()
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=csa_thread_object.dut_addr["dut_mac_address"],
            filter_name="probe_request",
        )
        probe_request_pkt = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter2
            + f" and frame.time_epoch >= {csa_dict_info['Epoch Time']}",
        )["packet_count"]
        assert (
            probe_request_pkt == False
        ), f"Probe Request to Access Point shouldn't be present as Quite Mode is ON"
        null_pkt = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=f"wlan.sa == {csa_thread_object.dut_addr['dut_mac_address']} && wlan.fc.type_subtype == 0x0024 "
            f"and frame.time_epoch >= {csa_dict_info['Epoch Time']}",
        )["packet_count"]
        assert null_pkt == False, "\n No Null Data Packets from DUT during CSA \n"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [4])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_csa_with_bgscan_during_rx_data_transfer_c779701(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
):
    try:
        beacon_count = 10
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=779609,
            sniffer_filter=sniffer_filter,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        """ Enabling BG scan """
        wifi_dut.interfaces.wifi.set_advanced_scan_configuration(
            adv_active_channel_time=15,
            adv_passive_channel_time=20,
            adv_trigger_level=20,
            adv_trigger_level_change=50,
        )
        logger().info("\n *** Enable BGscan *** \n")
        wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
        data_transfer_obj = DataTransfer(
            wifi_dut=wifi_dut,
            remote_socket_factory=remote_socket_factory,
            dut_addr=csa_thread_object.dut_addr,
            transfer_type="TX",
        )
        data_transfer_obj.start_remote_server()
        tx_thread = Thread(target=data_transfer_obj.transmit_tcp_data)
        csa_thread = Thread(
            target=wifi_access_point.interfaces.wifi.enable_disable_csa,
            args=(channel, beacon_count, True),
        )
        tx_thread.start()
        logger().info(f" <---- Initiating CSA ----> ")
        time.sleep(5)
        csa_thread.start()
        tx_thread.join()
        csa_dict_info = csa_thread_object.csa_sniffer_validation()
        null_pkt = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=f"wlan.sa == {csa_thread_object.dut_addr['dut_mac_address']} && wlan.fc.type_subtype == 0x0024 "
            f"and frame.time_epoch >= {csa_dict_info['Epoch Time']}",
        )["packet_count"]
        assert null_pkt == False, "\n No Null Data Packets from DUT during CSA \n"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket_factory.interfaces.socket.close_all()
