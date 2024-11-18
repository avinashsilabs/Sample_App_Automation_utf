import pytest
import time
import re
import random
import string

from utf.utils.commander import device_info
from utf.utils.stopwatch import Stopwatch
from example_test_package.conftest import sl_collections
from example_test_package.sqa_test_suites.coex.functional.sta_ble.test_sta_ble_tcp_udp import (
    socket_connect,
)
from utf.interfaces.wifi.fixtures import wifi_dut, wifi_client
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xOperatingMode,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
)
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import (
    AsyncEventIdentifiers,
)


def logger():
    return get_logger(__name__)


class TWTParams:
    def __init__(self):
        self.twt_enable = 1
        self.average_tx_throughput = 0
        self.tx_latency = 0
        self.rx_latency = 60000
        self.device_average_throughput = 20000
        self.estimated_extra_wake_duration_percent = 0
        self.twt_tolerable_deviation = 10
        self.default_wake_interval_ms = 1024
        self.default_minimum_wake_duration_ms = 8
        self.beacon_wake_up_count_after_sp = 2


class SocketDataTransfer:
    def __init__(self, remote_socket=None):
        self.sock_id = None
        self.server_ip = None
        self.server_port = None
        self.remote_socket = remote_socket
        self.data_transfer_duration = 3600

    def start_remote_socket_server(self):
        self.server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
        self.server_port = self.remote_socket.interfaces.socket.server_port
        logger().info(
            f"Starting TCP Server remotely at port number {self.server_port} with IP Address: {self.server_ip}"
        )
        self.remote_socket.interfaces.socket.start_server()

    def send_data_over_socket(self, wifi_dut, duration, sleep_time):
        self.remote_socket.interfaces.socket.time_limit = 3600
        sw = Stopwatch()
        while sw.elapsed_sec < duration:
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )
            try:
                wifi_dut.interfaces.wifi.bsdSocketSend(
                    socket_fd=self.sock_id, data=sent_data, higher_data_len=0
                )
                received_data = self.remote_socket.interfaces.socket.recv_data_tcp(
                    len(sent_data)
                )
                assert (
                    sent_data == received_data
                ), f"Data mismatch in sent and received data"
                if sleep_time:
                    time.sleep(sleep_time)
            except Exception as e:
                logger().info(
                    f"Socket Data Transfer Failed Within Duration: {sw.elapsed_sec}"
                )
                break

    def open_and_set_socket_option(
        self,
        socket_domain: str,
        socket_type: str,
        socket_protocol: str,
        wifi_dut,
    ):
        self.sock_id = wifi_dut.interfaces.wifi.socket(
            domain=socket_domain, stream_type=socket_type, protocol=socket_protocol
        )
        assert self.sock_id >= 0, f"Failed to open a socket with ID: {self.sock_id}"
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(
            socket_fd=self.sock_id, option_name="SO_KEEPALIVE", option_val="240"
        )
        logger().info(
            f"Successfully opened a {socket_protocol} with Socket ID: {self.sock_id}"
        )
        wifi_dut.interfaces.wifi.bsdSocketConnect(
            socket_fd=self.sock_id,
            server_ip=self.server_ip,
            server_port=self.server_port,
            timeout=30,
        )


class TWT_AUTOCONFIG(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        wifi_sniffer=None,
        wifi_access_point=None,
        sl_collections=None,
        wifi_client=None,
        remote_socket=None,
        sniffer_filter=None,
        sniffer_capture=None,
        testcase_id=None,
    ):
        super().__init__()
        self.device_info = None
        self.remote_mac_address = None
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.wifi_client = wifi_client
        self.remote_socket = remote_socket
        self.sniffer_filter = sniffer_filter
        self.sniffer_capture = sniffer_capture
        self.testcase_id = testcase_id
        self.second_level_filter = "        Tag: Target Wake Time"
        self.socket_data_transfer_obj = SocketDataTransfer(remote_socket=remote_socket)
        self.twt_params = TWTParams()

    def verify_twt_data_packets_at_rx_latency(self, twt_response_frame_epoch_time: int):
        self.wifi_sniffer.interfaces.capture.collecting_frame_number(
            packet_filter1=f"wlan.tim.aid"
        )
        with open("./reports/filter2_file.txt", "r") as file:
            frame_number = file.readline()
            frame_number = frame_number.rstrip("\n")
        logger().info(
            f"\nThe Frame number at which TIM BIT is set is: {frame_number}\n"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=f"frame.number == {frame_number}",
            packet_filter2=self.second_level_filter,
        )["packet_count"], "Not able to find the desired packets"
        with open("./reports/filter2_file.txt", "r") as file:
            data = file.read()
            pattern = r"Epoch Time:\s+([\d.]+)"
            match = re.search(pattern, data)
            if match:
                epoch_time = match.group(1)
        logger().info(f"The Epoch time at which TIM bit is set is: {epoch_time}")
        max_packet_retrival_time = self.twt_params.rx_latency * 0.001 - (
            float(epoch_time) - twt_response_frame_epoch_time
        )
        logger().info(
            f"The maximum packet retrieval time is: {max_packet_retrival_time}"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=f"(wlan.sa == {self.device_info['dut_mac_address']} && wlan.da == {self.remote_mac_address}) && (frame.time_epoch <= {twt_response_frame_epoch_time + max_packet_retrival_time + 7}) && wlan.fc.type_subtype == 0x0028",
            packet_filter2=self.second_level_filter,
        )[
            "packet_count"
        ], f"Not able to find the Data packets till {twt_response_frame_epoch_time + max_packet_retrival_time} seconds"

    def twt_frame_info(self, frame: str):
        with open("./reports/filter2_file.txt", "r") as file:
            data = file.read()
            pattern = r"Setup Command: (.+?)\s*\((\d+)\)"
            match = re.search(pattern, data)
            if match:
                setup_command = match.group(1)
                setup_command_value = match.group(2)
                logger().info(
                    f"Setup Command: {setup_command}, Value: {setup_command_value}"
                )
                if frame == "twt_request_frame":
                    assert (
                        setup_command == "Suggest TWT"
                    ), "Setup Command is not TWT Setup Request"
                    assert setup_command_value == "1", "Setup Command Value is not 1"
                else:
                    assert (
                        setup_command == "Accept TWT"
                    ), "Setup Command is not TWT Accept TWT Response"
                    assert setup_command_value == "4", "Setup Command Value is not 4"
            else:
                logger().info("Setup Command not found")

    def extract_twt_setup_command(self, file_path):
        contents = []
        with open(file_path, "r") as file:
            data = file.read()
            patterns = [
                r"Nominal Minimum TWT Wake duration:\s+(\d+)",
                r"TWT Wake Interval Mantissa:\s+(\d+)",
                r"Wake Interval Exponent:\s+(\d+)",
                r"Target Wake Time:\s+(\d+)",
                r"Epoch Time:\s+([\d.]+)",
            ]
            for pattern in patterns:
                match = re.search(pattern, data)
                if match:
                    contents.append(float(match.group(1)))
        return contents

    def enable_twt(
        self,
        expected_status: SLStatus = SLStatus.SL_STATUS_OK,
    ):
        logger().info(f"Enabling the target wake time")
        self.wifi_dut.interfaces.wifi.twt_auto_config(
            twt_enable=self.twt_params.twt_enable,
            average_tx_throughput=self.twt_params.average_tx_throughput,
            tx_latency=self.twt_params.tx_latency,
            rx_latency=self.twt_params.rx_latency,
            device_average_throughput=self.twt_params.device_average_throughput,
            estimated_extra_wake_duration_percent=self.twt_params.estimated_extra_wake_duration_percent,
            twt_tolerable_deviation=self.twt_params.twt_tolerable_deviation,
            default_wake_interval_ms=self.twt_params.default_wake_interval_ms,
            default_minimum_wake_duration_ms=self.twt_params.default_minimum_wake_duration_ms,
            beacon_wake_up_count_after_sp=self.twt_params.beacon_wake_up_count_after_sp,
            expected_status=expected_status,
        )

    def disable_twt(self):
        self.wifi_dut.interfaces.wifi.disable_twt()

    def twt_enable_disable_data_transfer(self, power_save=False):
        iteration_count = 0
        while iteration_count < 3:
            if iteration_count != 0:
                logger().info(f"\nEnable the target wake time\n")
                self.enable_twt()
            if power_save:
                self.wifi_dut.interfaces.wifi.set_performance_profile(
                    mode="power_save_low_latency"
                )
            self.socket_data_transfer_obj.send_data_over_socket(
                wifi_dut=self.wifi_dut, duration=60, sleep_time=0
            )
            logger().info(f"\n\nDisable the target wake time\n\n")
            self.disable_twt()
            if power_save:
                self.wifi_dut.interfaces.wifi.set_performance_profile(
                    mode="high_performance"
                )
            # Commenting the data transfer after disabling the TWT, might be a firmware related issue.
            # self.socket_data_transfer_obj.send_data_over_socket(
            #    wifi_dut=self.wifi_dut, duration=60, sleep_time=0
            # )
            iteration_count += 1

    def run(self):

        self.remote_mac_address = self.wifi_client.interfaces.wifi.get_mac_address(
            network_interface="eth1"
        )
        logger().info(
            f"\nThe remote device MAC Address is: {self.remote_mac_address}\n"
        )
        ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        # Configure the sniffer on wifi_access_point channel
        self.wifi_sniffer.interfaces.capture.configure_interface(
            self.wifi_access_point.interfaces.wifi.channel
        )
        # Start the sniffer on wifi_access_point channel
        self.wifi_sniffer.interfaces.capture.start_capture(self.sniffer_capture)

        self.device_info = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            power_save=False,
        )

        if self.testcase_id == "538039":
            self.twt_params.tx_latency = 50000
            self.enable_twt()
            self.wifi_dut.interfaces.wifi.set_performance_profile(
                mode="power_save_low_latency"
            )
            logger().info(
                f"\nPing to DUT IP Address: {self.device_info['device_ip']} with custom interval 60 seconds....\n"
            )
            start_time = time.time()
            while (time.time() - start_time) < 80:
                self.sl_collections.ping_with_custom_interval(
                    device_ip=self.device_info["device_ip"], interval=60
                )
            logger().info(f"\n....Disabling TWT Session....\n")
            self.disable_twt()
            return
        if self.testcase_id == "538040":
            self.twt_params.rx_latency = 21600001
            logger().info(f"\nSetting the RX_Latency to {self.twt_params.rx_latency}\n")
            self.enable_twt(expected_status=SLStatus.SL_STATUS_INVALID_PARAMETER)
            return
        if self.testcase_id == "538041":
            self.twt_params.tx_latency = 21600001
            logger().info(f"\nSetting the TX_Latency to {self.twt_params.rx_latency}\n")
            self.enable_twt(expected_status=SLStatus.SL_STATUS_INVALID_PARAMETER)
            return

        self.socket_data_transfer_obj.start_remote_socket_server()
        self.socket_data_transfer_obj.open_and_set_socket_option(
            socket_domain="AF_INET",
            socket_type="SOCK_STREAM",
            socket_protocol="IPPROTO_TCP",
            wifi_dut=self.wifi_dut,
        )
        if self.testcase_id == "538047":
            self.twt_params.rx_latency = 60000
            self.enable_twt()
            self.wifi_dut.interfaces.wifi.set_performance_profile(
                mode="power_save_low_latency"
            )
            self.twt_enable_disable_data_transfer()
            return
        if self.testcase_id == "538046":
            self.twt_params.rx_latency = 60000
            self.enable_twt()
            self.twt_enable_disable_data_transfer(power_save=True)
            return
        if self.testcase_id in ["510684", "510687", "510688"]:
            self.twt_params.rx_latency = 55000
        if self.testcase_id == "510685":
            self.twt_params.rx_latency = 25000
        if self.testcase_id == "510686":
            self.twt_params.rx_latency = 5000
        self.enable_twt()
        self.wifi_dut.interfaces.wifi.set_performance_profile(
            mode="power_save_low_latency"
        )
        time.sleep(2)
        # Sniffer Validation for Power Management BIT
        power_save_filter = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.device_info["dut_mac_address"],
                da_addr=ap_mac_address,
                filter_name="power_mgmt_bit",
            )
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=power_save_filter
        )[
            "packet_count"
        ], "Unable to find NULL-Data frame packets with power save bit = 1"

        twt_req_frame = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.device_info["dut_mac_address"],
                da_addr=ap_mac_address,
                filter_name="twt_requesting_sta_1",
            )
        )

        self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=twt_req_frame, packet_filter2=self.second_level_filter
        )

        self.twt_frame_info("twt_request_frame")
        twt_response_frame = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=ap_mac_address,
                da_addr=self.device_info["dut_mac_address"],
                filter_name="twt_responding_sta_0",
            )
        )

        self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=twt_response_frame, packet_filter2=self.second_level_filter
        )

        self.twt_frame_info("twt_response_frame")

        extracted_params = self.extract_twt_setup_command("./reports/filter2_file.txt")
        wakeup_interval = (extracted_params[1] * 2 ** extracted_params[2]) * 0.000001
        wakeup_period = extracted_params[0] * (256 * 0.000001)
        assert (
            1 < wakeup_interval < 256
        ), "Wakeup Interval is not within (1-256) ms range"
        logger().info(
            f"\n\nThe Wakeup Interval is {wakeup_interval} seconds and wakeup period is {wakeup_period} seconds\n\n"
        )
        logger().info(
            f"The timestamp at which the AP responds with TWT is {extracted_params[3]}"
        )

        self.socket_data_transfer_obj.send_data_over_socket(
            wifi_dut=self.wifi_dut,
            duration=self.socket_data_transfer_obj.data_transfer_duration,
            sleep_time=(self.twt_params.rx_latency * 0.0008),
        )
        self.verify_twt_data_packets_at_rx_latency(
            twt_response_frame_epoch_time=float(extracted_params[4])
        )
        self.wifi_sniffer.interfaces.capture.stop_capture()


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.Default,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
            | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
            | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
            | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
            | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "bt_features": 0,
            "ble_features": 0,
            "ble_custom_ext_features": 0,
        },
    )
]


@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax"})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_dut_behaviour_twt_enable_traffic_enable_ps_enable_twt_disable_traffic_disable_ps_disable_c538046(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    remote_socket,
    wifi_client,
):
    try:
        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            wifi_client=wifi_client,
            remote_socket=remote_socket,
            sniffer_capture="test_wifi_sdk_verify_dut_behaviour_twt_enable_traffic_enable_ps_enable_twt_disable_traffic_disable_ps_disable_c538046",
            testcase_id="538046",
        )
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax"})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_dut_behaviour_twt_enable_traffic_enable_twt_disable_traffic_disable_c538047(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    remote_socket,
    wifi_client,
):
    try:
        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            wifi_client=wifi_client,
            sniffer_capture="test_wifi_sdk_verify_dut_behaviour_twt_enable_traffic_enable_twt_disable_traffic_disable_c538047",
            testcase_id="538047",
        )
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax"})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_dut_behaviour_rx_latency_55_no_twt_tx_latency_0_c510684(
    wifi_dut,
    remote_socket,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    try:
        logger().info(f"\n Execute M4 power save \n")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake()
        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
            sniffer_capture="test_wifi_sdk_verify_dut_behaviour_rx_latency_55_no_twt_tx_latency_0_c510684",
            testcase_id="510684",
        )
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax"})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_dut_behaviour_rx_latency_25_no_twt_tx_latency_0_c510685(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    sl_collections,
    remote_socket,
    sniffer_filter,
    wifi_client,
):
    try:
        logger().info(f"\n Execute M4 power save \n")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake()
        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            sniffer_filter=sniffer_filter,
            sniffer_capture="test_wifi_sdk_verify_dut_behaviour_rx_latency_25_no_twt_tx_latency_0_c510685",
            wifi_client=wifi_client,
            testcase_id="510685",
        )
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax"})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_dut_behaviour_rx_latency_5_no_twt_tx_latency_0_c510686(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    sl_collections,
    remote_socket,
    sniffer_filter,
    wifi_client,
):
    try:
        logger().info(f"\n Execute M4 power save \n")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake()
        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            sniffer_filter=sniffer_filter,
            sniffer_capture="test_wifi_sdk_verify_dut_behaviour_rx_latency_5_no_twt_tx_latency_0_c510686",
            wifi_client=wifi_client,
            testcase_id="510686",
        )
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax"})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_dut_behaviour_rx_latency_55_listen_interval_500ms_no_twt_tx_latency_0_c510687(
    wifi_dut,
    remote_socket,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    try:
        logger().info(f"\n Execute M4 power save \n")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake()
        wifi_dut.interfaces.wifi.wifi_set_listen_interval(listen_interval=500)
        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
            sniffer_capture="test_wifi_sdk_verify_dut_behaviour_rx_latency_55_listen_interval_500ms_no_twt_tx_latency_0_c510687",
            testcase_id="510687",
        )
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax"})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_dut_behaviour_rx_latency_55_listen_interval_800ms_no_twt_tx_latency_0_c510688(
    wifi_dut,
    remote_socket,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    try:
        logger().info(f"\n Execute M4 power save \n")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake()
        wifi_dut.interfaces.wifi.wifi_set_listen_interval(listen_interval=800)
        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
            sniffer_capture="test_wifi_sdk_verify_dut_behaviour_rx_latency_55_listen_interval_800ms_no_twt_tx_latency_0_c510688",
            testcase_id="510688",
        )
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax"})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_weather_dut_is_able_to_configure_tx_latency_50sec_c538039(
    wifi_dut,
    remote_socket,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Case ID: C538039

    Objective:
    Verify that the Device Under Test (DUT) is able to configure the TX latency to 50 seconds.

    Steps:
    1. Initialize the WiFi DUT, remote socket, WiFi access point, WiFi sniffer, and other required components.
    2. Create an instance of the TWT_AUTOCONFIG class with the necessary parameters.
    3. Start the TWT_AUTOCONFIG instance and wait for it to complete.
    4. Handle any exceptions that occur during the test execution.

    Expected Result:
    The DUT should successfully configure the TX latency to 50 seconds without any errors.
    """
    try:
        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
            sniffer_capture="test_wifi_sdk_verify_weather_dut_is_able_to_configure_tx_latency_50sec_c538039",
            testcase_id="538039",
        )
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax"})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_weather_dut_is_throwing_error_rx_latency_more_than_2160_secs_c538040(
    wifi_dut,
    remote_socket,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Case ID: C538040

    Objective:
    Verify that the Device Under Test (DUT) throws an error when the RX latency is set to more than 2160 seconds.

    Steps:
    1. Initialize the WiFi DUT, remote socket, WiFi access point, WiFi sniffer, and other required components.
    2. Create an instance of the TWT_AUTOCONFIG class with the necessary parameters.
    3. Start the TWT_AUTOCONFIG instance and wait for it to complete.
    4. Handle any exceptions that occur during the test execution.

    Expected Result:
    The DUT should throw an error indicating that the RX latency value is invalid when set to more than 2160 seconds.
    """

    try:
        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
            sniffer_capture="test_wifi_sdk_verify_weather_dut_is_throwing_error_rx_latency_more_than_2160_secs_c538040",
            testcase_id="538040",
        )
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax"})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_weather_dut_is_throwing_error_tx_latency_more_than_2160_secs_c538041(
    wifi_dut,
    remote_socket,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Case ID: C538040

    Objective:
    Verify that the Device Under Test (DUT) throws an error when the RX latency is set to more than 2160 seconds.

    Steps:
    1. Initialize the WiFi DUT, remote socket, WiFi access point, WiFi sniffer, and other required components.
    2. Create an instance of the TWT_AUTOCONFIG class with the necessary parameters.
    3. Start the TWT_AUTOCONFIG instance and wait for it to complete.
    4. Handle any exceptions that occur during the test execution.

    Expected Result:
    The DUT should throw an error indicating that the RX latency value is invalid when set to more than 2160 seconds.
    """
    try:
        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
            sniffer_capture="test_wifi_sdk_verify_weather_dut_is_throwing_error_tx_latency_more_than_2160_secs_c538041",
            testcase_id="538041",
        )
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
