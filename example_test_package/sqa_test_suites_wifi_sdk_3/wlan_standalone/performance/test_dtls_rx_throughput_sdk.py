import time
import re
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xOperatingMode,
    Si91xExtCustomFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBSDSocketParams,
)
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from random import randint
from utf.utils.stopwatch import Stopwatch


def logger():
    return get_logger(__name__)


DTLS_RX_THROUGHPUT_TYPE = 7
DTLS_BUFFER_SIZE = 1370
DTLS_TEST_DURATION = 30
DTLS_IPERF_TIMEOUT = DTLS_TEST_DURATION + 20
WOLFSSL_SERVER_BIND_ADDRESS = "0.0.0.0"
WOLFSSL_SERVER_CERT = "server-cert.pem"
WOLFSSL_SERVER_KEY = "server-key.pem"

pytestmark = [pytest.mark.firmware_app("test_480K_M4SS_192K")]


def wifi_dut_marker(stack_len=None, thread_no=None, pmf_enable=False, priority=0):
    config = {
        "thread_config": {"wifi": {"count": thread_no if thread_no is not None else 1,
                                   "stack_len": stack_len if stack_len is not None else 3584, "priority": priority}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.SL_SI91X_TCP_IP_FEAT_DTLS_THREE_SOCKETS,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": (Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                (Si91xExtCustomFeatureBitMap.IEEE802_11W if pmf_enable else 0)),
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "set_send_feature_frame": True,
    }
    return pytest.mark.config("wifi_dut", wifi=config)


def wifi_dut_marker_coex(pmf_enable=False, priority=0):
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.SL_SI91X_TCP_IP_FEAT_DTLS_THREE_SOCKETS,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": (Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                (Si91xExtCustomFeatureBitMap.IEEE802_11W if pmf_enable else 0)),
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "set_send_feature_frame": True,
    }
    return pytest.mark.config("wifi_dut", wifi=config)


def parse_throughput(data: str) -> float:
    """Extract throughput value in Mbps from DUT iperf response."""
    match = re.search(r"Throughput achieved @ ([0-9.]+) Mbps", data)
    if match:
        return float(match.group(1))
    return 0.0


def parse_total_bytes_received(data: str) -> int:
    """Extract total bytes received from the DUT iperf response."""
    match = re.search(r"Total bytes received\s*:\s*([0-9]+)", data)
    if match:
        return int(match.group(1))
    return 0


def validate_dtls_rx_output(data: str) -> tuple[int, float]:
    """Validate that the DTLS_RX handler path ran and exchanged payload."""
    expected_messages = (
        "Load DTLS CA certificate at index 0 Success",
        "Load DTLS client certificate at index 0 Success",
        "Load DTLS client key at index 0 Success",
        "DTLS_RX Throughput test finished",
        "Total bytes received :",
        "Throughput achieved @",
    )

    for message in expected_messages:
        assert message in data, f"missing expected DUT output: {message}"

    bytes_received = parse_total_bytes_received(data)
    assert bytes_received > 0, "DTLS_RX completed without receiving payload data"

    throughput_mbps = parse_throughput(data)
    return bytes_received, throughput_mbps


class BleNotifyThread(ThreadBase):
    """Background thread that sends BLE notifications during DTLS Rx throughput test."""

    def __init__(self, wifi_dut, ble_client_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client_address = ble_client_address

    def run(self):
        data = "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdata"
        sw = Stopwatch()
        while sw.elapsed_sec < 35:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data,
                                                                  ble_remote_dev_address=self.ble_client_address)
            time.sleep(0.5)


class DtlsRxThread(ThreadBase):
    """Thread that drives the DTLS Rx throughput test sequence with optional BLE coex."""

    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None,
                 wolfssl=None, sl_collections=None, testcase=None, wifi_client=None,
                 async_socket=1, ble_conn=False, ble_data_transfer=False,
                 bt_dut=None, ble_client=None, utf_constants=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.wolfssl = wolfssl
        self.testcase = testcase
        self.server_ip = None
        self.local_port = None
        self.sl_collections = sl_collections
        self.wifi_client = wifi_client
        self.async_socket = async_socket
        self.throughput_mbps = 0.0
        self.ble_conn = ble_conn
        self.ble_data_transfer = ble_data_transfer
        self.bt_dut = bt_dut
        self.ble_client = ble_client
        self.utf_constants = utf_constants
        self.ble_client_address = None

    def run(self):
        logger().info("Starting sniffer capture")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        bt_dut_address = None
        bt_client_address = None
        char_path = None
        char_uid = None

        if self.ble_conn:
            conn_params = {
                "min_conn_interval": self.utf_constants.get("min_conn_interval"),
                "max_conn_interval": self.utf_constants.get("max_conn_interval"),
                "conn_latency": 0,
                "supervision_timeout": self.utf_constants.get("supervision_timeout")}
            logger().info("Initiate BLE service in DUT")
            bt_dut_address = self.bt_dut.interfaces.bluetooth.ble_start()
            assert bt_dut_address, "unable to fetch DUT BD address"

            logger().info("Set DUT in advertise mode")
            self.bt_dut.interfaces.bluetooth.ble_start_advertising()

            logger().info("Start SMP scan from the remote device")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(5)
            logger().info("Stop scanning")
            self.ble_client.interfaces.bluetooth.stop_scanning()

            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert self.bt_dut.interfaces.bluetooth.ble_address in found_devices

            self.ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                         min_conn_interval=conn_params["min_conn_interval"],
                                                         max_conn_interval=conn_params["max_conn_interval"],
                                                         conn_latency=conn_params["conn_latency"],
                                                         supervision_timeout=conn_params["supervision_timeout"])
            assert bt_dut_address, "unable to connect to the given address"
            time.sleep(5)

        if self.ble_data_transfer:
            service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
            char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

            logger().info("Start BLE in DUT")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address, "failed to initialize BLE in DUT"
            self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
            self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F)

            logger().info("Start BLE advertising in DUT")
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            logger().info("Start scanning in remote BLE device")
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address)
            assert self.ble_client_address, "failed to start scan in remote device"

            device_found = False
            sw = Stopwatch()
            while sw.elapsed_sec < 30:
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                if bt_dut_address in found_devices and \
                        found_devices[bt_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data:
                    device_found = True
                    break

            self.ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "no device found"

            logger().info("Connect to BLE DUT")
            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
            time.sleep(10)

            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "device is in disconnection state"

            servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            assert len(servs) > 0, "no services fetched"
            assert len(chars) > 0, "fetched characters are empty"

            char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=service_uid, char_uid=char_uid)
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"

            self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path, char_uid=char_uid)

        dut_addr = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            retry_count=3, ping_after_power_save=False, power_save=False)
        assert dut_addr, "failed to join DUT to the Wi-Fi network"
        time.sleep(2)

        try:
            if self.ble_data_transfer:
                logger().info("BLE Data Transfer is going to start")
                ble_data = BleNotifyThread(self.wifi_dut, self.ble_client_address)
                ble_data.start()

            self.local_port = randint(5001, 60000)
            self.server_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            assert self.server_ip, "failed to fetch WolfSSL server IP address"

            logger().info(f"Starting WolfSSL DTLS server on {self.server_ip}:{self.local_port}")
            self.wolfssl.interfaces.server.start(
                port=self.local_port,
                bind_address=WOLFSSL_SERVER_BIND_ADDRESS,
                udp=True,
                loop=False,
                echo=False,
                certfile=WOLFSSL_SERVER_CERT,
                keyfile=WOLFSSL_SERVER_KEY,
            )

            max_retries = 5
            for retry in range(max_retries):
                if self.wolfssl.interfaces.server.is_running():
                    logger().info(f"WolfSSL server confirmed running on port {self.local_port}")
                    break
                logger().warning(f"WolfSSL server not running, retry {retry + 1}/{max_retries}")
                time.sleep(1)
            else:
                raise RuntimeError(f"Failed to start WolfSSL server after {max_retries} retries")

            assert self.wolfssl.interfaces.server.is_running(), "WolfSSL server failed to start"
            time.sleep(2)

            # The DTLS_RX handler in `bsd_socket_commands.c` expects AF_INET/SOCK_DGRAM/IPPROTO_UDP
            # and selects the flow using throughput_type=7 with async_socket choosing the sync/async path.
            logger().info(f"Issuing iperf DTLS_RX command (throughput_type={DTLS_RX_THROUGHPUT_TYPE}, "
                          f"async_socket={self.async_socket})")
            _, data = self.wifi_dut.interfaces.wifi.iperf(
                family=Si91xBSDSocketParams.AF_INET,
                transfer_type=Si91xBSDSocketParams.SOCK_DGRAM,
                protocol=Si91xBSDSocketParams.IPPROTO_UDP,
                local_port=str(self.local_port),
                remote_ip=self.server_ip,
                remote_port=self.local_port,
                size=DTLS_BUFFER_SIZE,
                ttl=DTLS_TEST_DURATION,
                throughput_type=DTLS_RX_THROUGHPUT_TYPE,
                async_socket=self.async_socket,
                timeout=DTLS_IPERF_TIMEOUT,
            )

            bytes_received, self.throughput_mbps = validate_dtls_rx_output(data)
            logger().info(f"DTLS RX total bytes received: {bytes_received}")
            logger().info(f"DTLS RX throughput: {self.throughput_mbps} Mbps")
            logger().info(f"Raw iperf response: {data}")
        finally:
            if self.wolfssl.interfaces.server.is_running():
                self.wolfssl.interfaces.server.stop()
                time.sleep(1)

            if self.ble_conn and bt_client_address:
                self.bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
                time.sleep(2)

            if self.ble_data_transfer:
                ble_validation_data = "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdata"
                if char_path and char_uid:
                    logger().info("Unsubscribing BLE notifications")
                    self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                    self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                    time.sleep(1)

                    logger().info("Validate BLE Data")
                    notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                    logger().info(f"Notifications: {notifications}")
                    assert len(notifications) > 0, "received data is empty"
                    assert notifications[0] == ble_validation_data, "failed to fetch data"

                if bt_dut_address:
                    logger().info("BLE remove service")
                    self.wifi_dut.interfaces.wifi.ble_remove_service()

                    logger().info("Disconnecting BLE from DUT")
                    self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                    self.ble_client.interfaces.bluetooth.close()

            self.wifi_dut.interfaces.wifi.leave()
            time.sleep(2)
            self.wifi_sniffer.interfaces.capture.stop_capture()
            time.sleep(2)


# ---------------------------------------------------------------------------
# Standalone DTLS Rx throughput (async socket)
# ---------------------------------------------------------------------------
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
@pytest.mark.test_src_map_id('C768261')
def test_wifi_sdk_dtls_standalone_rx_async_C768261(firmware_loader, wifi_access_point, sniffer_filter, sl_collections,
                                                   wifi_dut, wolfssl, wifi_sniffer, request, wifi_client):
    testcase = request.node.name
    dtls_rx = DtlsRxThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, testcase=testcase,
                            sl_collections=sl_collections, wolfssl=wolfssl,
                            wifi_client=wifi_client, async_socket=1)
    try:
        dtls_rx.start()
        dtls_rx.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


# ---------------------------------------------------------------------------
# Standalone DTLS Rx throughput (sync socket)
# ---------------------------------------------------------------------------
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
@pytest.mark.test_src_map_id('C768263')
def test_wifi_sdk_dtls_standalone_rx_sync_C768263(firmware_loader, wifi_access_point, sniffer_filter, sl_collections,
                                                  wifi_dut, wolfssl, wifi_sniffer, request, wifi_client):
    testcase = request.node.name
    dtls_rx = DtlsRxThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, testcase=testcase,
                            sl_collections=sl_collections, wolfssl=wolfssl,
                            wifi_client=wifi_client, async_socket=0)
    try:
        dtls_rx.start()
        dtls_rx.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


# ---------------------------------------------------------------------------
# DTLS Rx throughput with BLE connected (async socket, coex mode)
# ---------------------------------------------------------------------------
@wifi_dut_marker_coex()
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
@pytest.mark.test_src_map_id('C768265')
def test_wifi_sdk_dtls_rx_with_ble_connected_C768265(firmware_loader, wifi_access_point, sniffer_filter, sl_collections, wifi_dut,
                                                     utf_constants, wolfssl, wifi_sniffer, request, wifi_client,
                                                     ble_client, bt_dut):
    testcase = request.node.name
    dtls_rx = DtlsRxThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, testcase=testcase,
                            sl_collections=sl_collections, wolfssl=wolfssl,
                            wifi_client=wifi_client, async_socket=1,
                            ble_conn=True, bt_dut=bt_dut, ble_client=ble_client,
                            utf_constants=utf_constants)
    try:
        dtls_rx.start()
        dtls_rx.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


# ---------------------------------------------------------------------------
# DTLS Rx throughput with BLE connected + data transfer (async socket, coex mode)
# ---------------------------------------------------------------------------
@wifi_dut_marker_coex()
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
@pytest.mark.test_src_map_id('C768267')
def test_wifi_sdk_dtls_rx_ble_conn_with_data_C768267(firmware_loader, wifi_access_point, sniffer_filter, sl_collections, wifi_dut,
                                                     utf_constants, wolfssl, wifi_sniffer, request, wifi_client,
                                                     ble_client, bt_dut):
    testcase = request.node.name
    dtls_rx = DtlsRxThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, testcase=testcase,
                            sl_collections=sl_collections, wolfssl=wolfssl,
                            wifi_client=wifi_client, async_socket=1,
                            ble_data_transfer=True, bt_dut=bt_dut, ble_client=ble_client,
                            utf_constants=utf_constants)
    try:
        dtls_rx.start()
        dtls_rx.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
