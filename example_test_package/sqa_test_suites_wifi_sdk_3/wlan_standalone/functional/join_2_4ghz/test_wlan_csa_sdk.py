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
)
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
        channel=11,
        beacon_count=4,
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
            ]
            for pattern in patterns:
                match = re.search(pattern, data)
                if match:
                    csa_dict_info[pattern.split(":")[0]] = match.group(1)
        return csa_dict_info

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

    def run(self):
        """
        Executes the thread's main logic for handling CSA operations.
        Depending on the test case ID, it performs data transfer (TX or RX)
        and initiates CSA on the access point.
        """
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=self.request.node.name
        )
        self.dut_addr = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            power_save=False,
        )
        if self.testcase_id != 776233:
            self.wifi_dut.interfaces.wifi.set_performance_profile(
                mode="power_save_low_latency"
            )
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
                args=(self.channel, self.beacon_count, True),
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
                args=(self.channel, self.beacon_count, True),
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
                args=(self.channel, self.beacon_count, True),
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
                args=(self.channel, self.beacon_count, True),
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
        while sw.elapsed_sec < 10:
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


def wifi_dut_fixture():
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
        | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
    return pytest.mark.config("wifi_dut", wifi=config)


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_check_dut_behaviour_during_rx_data_transfer_when_csa_is_received_c776228(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
):
    """
    Test the behavior of the Device Under Test (DUT) during RX data transfer
    when a Channel Switch Announcement (CSA) is received.

    Args:
        wifi_dut: The Wi-Fi device under test.
        wifi_access_point: The Wi-Fi access point used in the test.
        wifi_sniffer: The Wi-Fi sniffer for capturing packets.
        sl_collections: SLCollections instance for managing Wi-Fi operations.
        request: The pytest request object for the test.
        remote_socket_factory: Factory for creating remote sockets.
        sniffer_filter: Filter for analyzing sniffer-captured packets.
        channel (int): The channel to switch to during the CSA.

    Steps:
        1. Capture the current channel of the access point.
        2. Start a thread to handle the CSA process and RX data transfer.
        3. Wait for the thread to complete.
        4. Validate the presence of CSA packets in the sniffer capture.
        5. Verify the new channel number in the CSA information matches the expected channel.
        6. Ensure the access point's channel changes after the CSA.

    Assertions:
        - CSA packets are present in the sniffer capture.
        - The new channel number in the CSA matches the expected channel.
        - The access point's channel changes after the CSA.

    Exception Handling:
        - Logs and handles any exceptions that occur during the test.

    """
    try:
        channel_before_csa = wifi_access_point.interfaces.wifi.channel
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776228,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_access_point.interfaces.wifi.bssid,
            filter_name="channel_switch_announcement",
        )
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1,
            packet_filter2="       Tag: Channel Switch Announcement",
        )["packet_count"]
        csa_dict_info = WLANCSAThread.channel_switch_info_element()
        logger().info(f"\n The CSA Info Element is: {csa_dict_info} \n")
        assert (
            snif_pkt_count
        ), "\n Channel Switch Announcement Packet Present in Sniffer Capture \n"
        assert (
            int(csa_dict_info["New Channel Number"]) == channel
        ), f" **** Switched Channel doesn't match the Set Channel **** "

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_check_dut_behaviour_during_tx_data_transfer_when_csa_is_received_c776229(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    request,
    remote_socket_factory,
    sniffer_filter,
    channel,
):
    """
    Test the behavior of the Device Under Test (DUT) during TX data transfer
    when a Channel Switch Announcement (CSA) is received.

    Args:
        wifi_dut: The Wi-Fi device under test.
        wifi_access_point: The Wi-Fi access point used in the test.
        wifi_sniffer: The Wi-Fi sniffer for capturing packets.
        sl_collections: SLCollections instance for managing Wi-Fi operations.
        request: The pytest request object for the test.
        remote_socket_factory: Factory for creating remote sockets.
        sniffer_filter: Filter for analyzing sniffer-captured packets.
        channel (int): The channel to switch to during the CSA.

    Steps:
        1. Capture the current channel of the access point.
        2. Start a thread to handle the CSA process and TX data transfer.
        3. Wait for the thread to complete.
        4. Validate the presence of CSA packets in the sniffer capture.
        5. Verify the new channel number in the CSA information matches the expected channel.
        6. Ensure the access point's channel changes after the CSA.

    Assertions:
        - CSA packets are present in the sniffer capture.
        - The new channel number in the CSA matches the expected channel.
        - The access point's channel changes after the CSA.

    Exception Handling:
        - Logs and handles any exceptions that occur during the test.
    """
    try:
        channel_before_csa = wifi_access_point.interfaces.wifi.channel
        csa_thread_object = WLANCSAThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            request=request,
            remote_socket_factory=remote_socket_factory,
            channel=channel,
            testcase_id=776229,
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_access_point.interfaces.wifi.bssid,
            filter_name="channel_switch_announcement",
        )
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1,
            packet_filter2="       Tag: Channel Switch Announcement",
        )["packet_count"]
        csa_dict_info = WLANCSAThread.channel_switch_info_element()
        logger().info(f"\n The CSA Info Element is: {csa_dict_info} \n")
        assert (
            snif_pkt_count
        ), "\n Channel Switch Announcement Packet Present in Sniffer Capture \n"
        assert (
            int(csa_dict_info["New Channel Number"]) == channel
        ), f" **** Switched Channel doesn't match the Set Channel **** "

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [11])
@pytest.mark.parametrize("beacon_count", [1])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_check_dut_behaviour_when_csa_is_received_with_minimum_switch_count_c776230(
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
    """
    Test the behavior of the Device Under Test (DUT) when a Channel Switch Announcement (CSA)
    is received with the minimum switch count.

    Args:
        wifi_dut: The Wi-Fi device under test.
        wifi_access_point: The Wi-Fi access point used in the test.
        wifi_sniffer: The Wi-Fi sniffer for capturing packets.
        sl_collections: SLCollections instance for managing Wi-Fi operations.
        request: The pytest request object for the test.
        remote_socket_factory: Factory for creating remote sockets.
        sniffer_filter: Filter for analyzing sniffer-captured packets.
        channel (int): The channel to switch to during the CSA.
        beacon_count (int): The minimum number of beacons to send during the CSA.

    Steps:
        1. Capture the current channel of the access point.
        2. Start a thread to handle the CSA process with the minimum switch count.
        3. Wait for the thread to complete.
        4. Validate the presence of CSA packets in the sniffer capture.
        5. Verify the new channel number in the CSA information matches the expected channel.
        6. Ensure the access point's channel changes after the CSA.

    Assertions:
        - CSA packets are present in the sniffer capture.
        - The new channel number in the CSA matches the expected channel.
        - The access point's channel changes after the CSA.

    Exception Handling:
        - Logs and handles any exceptions that occur during the test.
    """
    try:
        channel_before_csa = wifi_access_point.interfaces.wifi.channel
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
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_access_point.interfaces.wifi.bssid,
            filter_name="channel_switch_announcement",
        )
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1,
            packet_filter2="       Tag: Channel Switch Announcement",
        )["packet_count"]
        csa_dict_info = WLANCSAThread.channel_switch_info_element()
        logger().info(f"\n The CSA Info Element is: {csa_dict_info} \n")
        assert (
            snif_pkt_count
        ), "\n Channel Switch Announcement Packet Present in Sniffer Capture \n"
        assert (
            int(csa_dict_info["New Channel Number"]) == channel
        ), f" **** Switched Channel doesn't match the Set Channel **** "

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [11])
@pytest.mark.parametrize("beacon_count", [255])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_check_dut_behaviour_when_csa_is_received_with_maximum_switch_count_c776231(
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
    """
    Test the behavior of the Device Under Test (DUT) when a Channel Switch Announcement (CSA)
    is received with the maximum switch count.

    Args:
        wifi_dut: The Wi-Fi device under test.
        wifi_access_point: The Wi-Fi access point used in the test.
        wifi_sniffer: The Wi-Fi sniffer for capturing packets.
        sl_collections: SLCollections instance for managing Wi-Fi operations.
        request: The pytest request object for the test.
        remote_socket_factory: Factory for creating remote sockets.
        sniffer_filter: Filter for analyzing sniffer-captured packets.
        channel (int): The channel to switch to during the CSA.
        beacon_count (int): The maximum number of beacons to send during the CSA.

    Steps:
        1. Capture the current channel of the access point.
        2. Start a thread to handle the CSA process with the maximum switch count.
        3. Wait for the thread to complete.
        4. Validate the presence of CSA packets in the sniffer capture.
        5. Verify the new channel number in the CSA information matches the expected channel.
        6. Ensure the access point's channel changes after the CSA.

    Assertions:
        - CSA packets are present in the sniffer capture.
        - The new channel number in the CSA matches the expected channel.
        - The access point's channel changes after the CSA.

    Exception Handling:
        - Logs and handles any exceptions that occur during the test.
    """
    try:
        channel_before_csa = wifi_access_point.interfaces.wifi.channel
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
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_access_point.interfaces.wifi.bssid,
            filter_name="channel_switch_announcement",
        )
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1,
            packet_filter2="       Tag: Channel Switch Announcement",
        )["packet_count"]
        csa_dict_info = WLANCSAThread.channel_switch_info_element()
        logger().info(f"\n The CSA Info Element is: {csa_dict_info} \n")
        assert (
            snif_pkt_count
        ), "\n Channel Switch Announcement Packet Present in Sniffer Capture \n"
        assert (
            int(csa_dict_info["New Channel Number"]) == channel
        ), f" **** Switched Channel doesn't match the Set Channel **** "

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()


@wifi_dut_fixture()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"channel": 6, "security": "WPA2"})
@pytest.mark.parametrize("channel", [11])
@pytest.mark.parametrize("beacon_count", [4])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_check_dut_behaviour_when_csa_is_received_with_ap_switching_to_unsupported_region_c776232(
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
    """
    Test the behavior of the Device Under Test (DUT) when a Channel Switch Announcement (CSA)
    is received, and the access point switches to an unsupported region.

    Args:
        wifi_dut: The Wi-Fi device under test.
        wifi_access_point: The Wi-Fi access point used in the test.
        wifi_sniffer: The Wi-Fi sniffer for capturing packets.
        sl_collections: SLCollections instance for managing Wi-Fi operations.
        request: The pytest request object for the test.
        remote_socket_factory: Factory for creating remote sockets.
        sniffer_filter: Filter for analyzing sniffer-captured packets.
        channel (int): The channel to switch to during the CSA.
        beacon_count (int): The number of beacons to send during the CSA.

    Steps:
        1. Capture the current channel of the access point.
        2. Start a thread to handle the CSA process with the access point switching to an unsupported region.
        3. Wait for the thread to complete.
        4. Validate the presence of CSA packets in the sniffer capture.
        5. Verify the new channel number in the CSA information matches the expected channel.
        6. Validate that the DUT sends a probe request to reconnect to the access point after switching to the unsupported region.

    Assertions:
        - CSA packets are present in the sniffer capture.
        - The new channel number in the CSA matches the expected channel.
        - The DUT sends a probe request to reconnect to the access point.

    Exception Handling:
        - Logs and handles any exceptions that occur during the test.
    """
    try:
        channel_before_csa = wifi_access_point.interfaces.wifi.channel
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
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_access_point.interfaces.wifi.bssid,
            filter_name="channel_switch_announcement",
        )
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1,
            packet_filter2="       Tag: Channel Switch Announcement",
        )["packet_count"]
        csa_dict_info = WLANCSAThread.channel_switch_info_element()
        logger().info(f"\n The CSA Info Element is: {csa_dict_info} \n")
        assert (
            snif_pkt_count
        ), "\n Channel Switch Announcement Packet Present in Sniffer Capture \n"
        assert (
            int(csa_dict_info["New Channel Number"]) == channel
        ), f" **** Switched Channel doesn't match the Set Channel **** "
        logger().info(
            f"\n Validating the Probe Request DUT will send to establish a Connection after switching to Unsupported Region Channel: {channel}\n"
        )
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=csa_thread_object.dut_addr["dut_mac_address"],
            filter_name="probe_request",
        )
        probe_request_pkt = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter2,
        )["packet_count"]
        assert (
            probe_request_pkt > 0
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
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_check_dut_behaviour_during_http_otaf_upgrade_when_csa_is_received_c776233(
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
    """
    Test DUT behavior during HTTP OTAF upgrade when CSA is received.

    Validates that the DUT can successfully complete firmware upgrade via HTTP OTAF
    even when the access point initiates a channel switch during the upgrade process.

    Args:
        wifi_dut: Wi-Fi device under test with HTTP OTAF capabilities.
        wifi_access_point: Access point configured on channel 6.
        wifi_sniffer: Packet capture and analysis tool.
        sl_collections: Wi-Fi operations manager.
        request: Pytest request object.
        remote_socket_factory: Remote socket factory.
        sniffer_filter: Packet filter for CSA analysis.
        channel: Target channel (11) for CSA.
        http_server: HTTP server for firmware files.
        utf_constants: Test framework constants.

    Steps:
        1. Join DUT to access point network.
        2. Start HTTP OTAF firmware upgrade.
        3. Trigger CSA to switch to channel 11 after 15 seconds.
        4. Verify upgrade completes successfully.
        5. Validate CSA packets and channel switch.

    Assertions:
        - HTTP server is accessible.
        - CSA packets are captured.
        - Channel switches to expected channel.
        - Firmware version changes after upgrade.
    """
    try:
        channel_before_csa = wifi_access_point.interfaces.wifi.channel
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
        )
        csa_thread_object.start()
        csa_thread_object.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_access_point.interfaces.wifi.bssid,
            filter_name="channel_switch_announcement",
        )
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1,
            packet_filter2="       Tag: Channel Switch Announcement",
        )["packet_count"]
        csa_dict_info = WLANCSAThread.channel_switch_info_element()
        logger().info(f"\n The CSA Info Element is: {csa_dict_info} \n")
        assert (
            snif_pkt_count
        ), "\n Channel Switch Announcement Packet Present in Sniffer Capture \n"
        assert (
            int(csa_dict_info["New Channel Number"]) == channel
        ), f" **** Switched Channel doesn't match the Set Channel **** "

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
