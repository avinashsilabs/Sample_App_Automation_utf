import random
import string
import time
import pytest

from utf.utf_config import UtfConfig
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wifi_zephyr.devices.si91x import (
    Si91xBSDSocketParams,
    WiFiPs,
    WiFiPsParamType,
    WiFiPsWakeupMode,
)

"""
    Setup requirement:
        1. SoC board
        2. Raspberry PI4
        3. Access Point
        4. Sniffer (NUC device)
        5. Remote socket server/client setup for TCP traffic

    Test Steps:
        1. Configure the DUT in WLAN alone mode and connect it to the access point
        2. Enable DHCP or assign IP configuration after connection
        3. Enable listen-interval based power save on the DUT
        4. Start sniffer capture and initiate long-run TCP traffic based on the test scenario
        5. Validate long-run power save behavior, connectivity, and traffic stability throughout the test duration

    Author: Vinod.G
"""

LONG_RUN_LISTEN_INTERVAL = 800
LONG_RUN_LISTEN_INTERVAL_TEST_CASES = ('1742324', '1742325')
#LONG_RUN_DURATION_SEC = 12 * 60 * 60
LONG_RUN_DURATION_SEC = 20 * 60
TCP_TRAFFIC_INTERVAL_SEC = 10 * 60
TCP_SERVER_PORT = 5001
TCP_DATA_LENGTH = 100

WIFI_PS_LISTEN_INTERVAL_DRIVER_MAX = 10
WIFI_PS_WAKEUP_MODE_TEXT = {
    WiFiPsWakeupMode.DTIM: "DTIM",
    WiFiPsWakeupMode.ListenInterval: "Listen interval",
}


def logger():
    return get_logger(__name__)


def get_effective_listen_interval(configured_listen_interval: int) -> int:
    """Return listen interval as reported by wifi_ps_config after driver clamping."""
    if configured_listen_interval == 0:
        return 0
    return min(configured_listen_interval, WIFI_PS_LISTEN_INTERVAL_DRIVER_MAX)


def validate_power_save_wakeup_mode(ps_config, expected_wakeup_mode: WiFiPsWakeupMode):
    expected_text = WIFI_PS_WAKEUP_MODE_TEXT[expected_wakeup_mode]
    wakeup_mode = ps_config.get("wakeup_mode")
    assert wakeup_mode == expected_text, (
        f"Expected {expected_wakeup_mode.name}-based power save "
        f"(wakeup_mode={expected_text!r}), got {wakeup_mode!r}. "
        f"Full PS config: {ps_config}"
    )


def validate_power_save_listen_interval(ps_config, configured_listen_interval: int):
    expected_listen_interval = get_effective_listen_interval(configured_listen_interval)
    listen_interval = ps_config.get("listen_interval")
    assert listen_interval == expected_listen_interval, (
        f"Expected listen_interval={expected_listen_interval} "
        f"(configured={configured_listen_interval}), got {listen_interval!r}. "
        f"Full PS config: {ps_config}"
    )


class WifiLongRun(ThreadBase):
    """Long-run power save tests: join with PS, then run extended traffic."""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, wifi_client=None,
                 capture_filename=None, zephyr_wifi_collections=None, power_save=None, test_case=None,
                 remote_socket=None, tcp_server_port=TCP_SERVER_PORT, tcp_data_length=TCP_DATA_LENGTH):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.wifi_client = wifi_client
        self.capture_filename = capture_filename
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.power_save = power_save
        self.test_case = test_case
        self.remote_socket = remote_socket
        self.tcp_server_port = tcp_server_port
        self.tcp_data_length = tcp_data_length
        self.dut_addr = None
        self.ps_config = None
        self._sniffer_started = False
        self._tcp_socket_id = None

    def _configure_and_join_with_power_save(self):
        """Join AP and enable power save based on test_case configuration."""
        configured_listen_interval = None
        if self.test_case in LONG_RUN_LISTEN_INTERVAL_TEST_CASES:
            configured_listen_interval = LONG_RUN_LISTEN_INTERVAL
            self.wifi_dut.interfaces.wifi.wifi_ps(
                param_type=WiFiPsParamType.ListenInterval,
                listen_interval=configured_listen_interval,
            )
        self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
            self.wifi_dut,
            self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            retry_count=3,
            power_save=False,
            ping_after_power_save=False,
        )
        if self.test_case in LONG_RUN_LISTEN_INTERVAL_TEST_CASES:
            self.wifi_dut.interfaces.wifi.wifi_ps(
                param_type=WiFiPsParamType.WakeupMode,
                wakeup_mode=WiFiPsWakeupMode.ListenInterval,
            )
            self.wifi_dut.interfaces.wifi.wifi_ps(
                param_type=WiFiPsParamType.State,
                enabled=WiFiPs.Enabled,
            )
            self.ps_config = self.wifi_dut.interfaces.wifi.wifi_ps_config()
            logger().info(f"WiFi PS config after join: {self.ps_config}")
            validate_power_save_wakeup_mode(self.ps_config, WiFiPsWakeupMode.ListenInterval)
            validate_power_save_listen_interval(self.ps_config, configured_listen_interval)
        return self.dut_addr

    def start_sniffer_capture(self):
        """Start sniffer capture if not already started."""
        if self._sniffer_started:
            return
        logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        self._sniffer_started = True

    def run(self):
        try:
            self.start_sniffer_capture()
            self._configure_and_join_with_power_save()
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
            raise

    def tcp_client_connect(self, server_ip):
        """Open TCP client socket, bind, and connect to server (ref: C19347)."""
        logger().info("Starting remote TCP server")
        self.remote_socket.interfaces.socket.start_server(port=self.tcp_server_port)
        socket_id = self.wifi_dut.interfaces.wifi.socket(
            domain=Si91xBSDSocketParams.AF_INET,
            stream_type=Si91xBSDSocketParams.SOCK_STREAM,
            protocol=Si91xBSDSocketParams.IPPROTO_TCP,
        )
        logger().info(f"Socket opened successfully: {socket_id}")
        self.wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_id,
            device_ip=self.dut_addr['device_ip'],
            port=self.tcp_server_port,
            timeout=5,
        )

        logger().info("DUT connecting to TCP server")
        connect_status = False
        for retry in range(3):
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_id, server_ip, self.tcp_server_port)
                connect_status = True
                break
            except Exception:
                logger().info(f"Socket connection failed, retry {retry + 1}/3")
        assert connect_status, "TCP socket connection failed on DUT"
        logger().info("TCP socket connection successful")
        self._tcp_socket_id = socket_id
        return socket_id

    def tcp_client_send_data(self, data_length=None):
        """Send data on an established TCP connection and verify at server."""
        if data_length is None:
            data_length = self.tcp_data_length
        sent_data = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=data_length)
        )
        status, _ = self.wifi_dut.interfaces.wifi.send(
            socket_fd=self._tcp_socket_id, data=sent_data)
        assert status == 0, f"TCP send failed with status {status}"
        received_data = self.remote_socket.interfaces.socket.recv_data_tcp(len(sent_data))
        logger().info(f"Received data length: {len(received_data)}")
        assert sent_data == received_data, "Data mismatch between sent and received TCP payload"

    def tcp_client_receive_data(self, data_length=None):
        """Receive data on an established TCP connection and verify against server send."""
        if data_length is None:
            data_length = self.tcp_data_length
        sent_data = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=data_length)
        )
        self.remote_socket.interfaces.socket.send_data_tcp(
            sent_data, use_server_socket=True)
        received_data = self.wifi_dut.interfaces.wifi.recv(
            self._tcp_socket_id, data_length)
        logger().info(f"Received data length: {len(received_data)}")
        assert sent_data == received_data, "Data mismatch between sent and received TCP payload"

    def tcp_client_disconnect(self):
        """Close TCP client socket and stop remote server."""
        if self._tcp_socket_id is not None:
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self._tcp_socket_id)
            self._tcp_socket_id = None
        logger().info("Stopping remote TCP server")
        self.remote_socket.interfaces.socket.stop()

    def run_tcp_send_every_interval_for_duration(self, server_ip,
                                                 duration_sec=LONG_RUN_DURATION_SEC,
                                                 interval_sec=TCP_TRAFFIC_INTERVAL_SEC):
        """Keep one TCP connection open; send data every interval_sec for duration_sec."""
        self.tcp_client_connect(server_ip=server_ip)

        end_time = time.time() + duration_sec
        iteration = 0
        try:
            while time.time() < end_time:
                iteration += 1
                remaining_min = int((end_time - time.time()) / 60)
                logger().info(
                    f"TCP send iteration {iteration}: ~{remaining_min} minutes remaining in "
                    f"{duration_sec // 3600}-hour run"
                )
                self.tcp_client_send_data()
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                sleep_sec = min(interval_sec, remaining)
                logger().info(
                    f"Sleeping {sleep_sec // 60} minutes until next TCP send "
                    f"({iteration} completed)"
                )
                time.sleep(sleep_sec)
        finally:
            self.tcp_client_disconnect()

        logger().info(
            f"Completed TCP send every {interval_sec // 60} minutes on persistent connection for "
            f"{duration_sec // 3600} hours in {iteration} iterations"
        )

    def run_tcp_receive_every_interval_for_duration(self, server_ip,
                                                    duration_sec=LONG_RUN_DURATION_SEC,
                                                    interval_sec=TCP_TRAFFIC_INTERVAL_SEC):
        """Keep one TCP connection open; receive data every interval_sec for duration_sec."""
        self.tcp_client_connect(server_ip=server_ip)

        end_time = time.time() + duration_sec
        iteration = 0
        try:
            while time.time() < end_time:
                iteration += 1
                remaining_min = int((end_time - time.time()) / 60)
                logger().info(
                    f"TCP receive iteration {iteration}: ~{remaining_min} minutes remaining in "
                    f"{duration_sec // 3600}-hour run"
                )
                self.tcp_client_receive_data()
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                sleep_sec = min(interval_sec, remaining)
                logger().info(
                    f"Sleeping {sleep_sec // 60} minutes until next TCP receive "
                    f"({iteration} completed)"
                )
                time.sleep(sleep_sec)
        finally:
            self.tcp_client_disconnect()

        logger().info(
            f"Completed TCP receive every {interval_sec // 60} minutes on persistent connection for "
            f"{duration_sec // 3600} hours in {iteration} iterations"
        )


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_tcp_send_listen_interval_ps_long_run_c1742324(
        wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, request,
        zephyr_wifi_collections, remote_socket, sniffer_filter):
    """Verify TCP send every 10 minutes for 12 hours on one connection with listen-interval PS (LI=800)."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiLongRun(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            wifi_client=wifi_client,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742324',
            remote_socket=remote_socket,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        logger().info(f"TCP server IP: {server_ip}, DUT IP: {wifi_obj.dut_addr['device_ip']}")

        wifi_obj.run_tcp_send_every_interval_for_duration(server_ip=server_ip)

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        zephyr_wifi_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_addr['dut_mac_address'],
            ap_mac_address,
            sniffer_filter,
            power_save=power_save,
        )

    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_tcp_receive_listen_interval_ps_long_run_c1742325(
        wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, request,
        zephyr_wifi_collections, remote_socket, sniffer_filter):
    """Verify TCP receive every 10 minutes for 12 hours on one connection with listen-interval PS (LI=800)."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiLongRun(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            wifi_client=wifi_client,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742325',
            remote_socket=remote_socket,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        logger().info(f"TCP server IP: {server_ip}, DUT IP: {wifi_obj.dut_addr['device_ip']}")

        wifi_obj.run_tcp_receive_every_interval_for_duration(server_ip=server_ip)

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        zephyr_wifi_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_addr['dut_mac_address'],
            ap_mac_address,
            sniffer_filter,
            power_save=power_save,
        )

    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
