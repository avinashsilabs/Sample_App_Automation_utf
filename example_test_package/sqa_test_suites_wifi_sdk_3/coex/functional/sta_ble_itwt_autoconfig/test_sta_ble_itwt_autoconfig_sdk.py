from utf.interfaces.socket import SOCKET_TYPE_TCP, SOCKET_TYPE_UDP
import re
import time
import string
import random
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import (BodySensorLocationCharacteristic,
                                                                                HeartRateControlPointCharacteristic,
                                                                                HeartRateMeasurementCharacterstic)
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xOperatingMode,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap,Si91xBLEFeatureBitMap,
    Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes,
    Si91xJoinFeatureBitMap,
)
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.wifi.fixtures import wifi_dut, wifi_client
from example_test_package.sqa_test_suites.coex.functional.sta_ble.test_sta_ble_modes import ble_client_address
ble_obj= None

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
        self.data_transfer_duration = 60

    def start_remote_socket_server(self, socket_type):
        logger().info(f"The socket_ype is {socket_type}")
        self.server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
        self.server_port = self.remote_socket.interfaces.socket.server_port
        logger().info(
            f"Starting {'UDP_SERVER' if socket_type else 'TCP_SERVER'} remotely at port number {self.server_port} with IP Address: {self.server_ip}"
        )
        self.remote_socket.interfaces.socket.start_server(socket_type=socket_type)

    def send_data_over_socket(
        self, wifi_dut, duration, sleep_time, socket_type=SOCKET_TYPE_TCP
    ):
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
                received_data = (
                    self.remote_socket.interfaces.socket.recv_data_tcp(len(sent_data))
                    if socket_type == SOCKET_TYPE_TCP
                    else self.remote_socket.interfaces.socket.recv_data_udp(
                        len(sent_data)
                    )[0]
                )
                logger().info(f"\nReceived Data: {received_data}\n")
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
        ping_count=None,
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
        self.power_save = None
        self.ping_count = ping_count

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
        #iteration_count = 0
        for iteration_count in range(0,3):  #while iteration_count < 3:
            if power_save:
                logger().info(f"\n\nEnable Power save mode\n\n")
                self.set_power_save()
            logger().info(f"\n\nSend data over socket\n\n")
            self.socket_data_transfer_obj.send_data_over_socket(
                wifi_dut=self.wifi_dut, duration=60, sleep_time=0
            )
            logger().info(f"\n\nDisable the target wake time\n\n")
            self.disable_twt()
            if power_save:
                logger().info(f"\n\nDisable Power save mode\n\n")
                self.wifi_dut.interfaces.wifi.set_performance_profile(
                    mode="high_performance"
                )
            logger().info(f"\n\nSend data over socket\n\n")
            self.socket_data_transfer_obj.send_data_over_socket(
                wifi_dut=self.wifi_dut, duration=60, sleep_time=0
            )
            #iteration_count += 1

    def join_to_ap(self):
        self.wifi_sniffer.interfaces.capture.start_capture(self.sniffer_capture)
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.sniffer_capture)

        if not self.wifi_dut.interfaces.wifi.associated:
            logger().info("Enabling rejoin parameters")
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
                max_retry_attempts=0,
                scan_interval=4,
                beacon_missed_count=40,
                first_time_retry_enable=0,
            )
            if self.power_save:
                logger().info(f"Configuring Listen interval based power save")
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                  Si91xJoinFeatureBitMap.ListenIntervalFromJoin)

            self.remote_mac_address = self.wifi_client.interfaces.wifi.get_mac_address()
            self.remote_host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(
                f"\nThe remote device MAC Address is: {self.remote_mac_address} and host_ip is {self.remote_host_ip}\n"
            )

            self.device_info = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                associated=self.wifi_dut.interfaces.wifi.associated,
                power_save=False,
            )

    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

    def set_power_save(self):

        self.wifi_dut.interfaces.wifi.set_performance_profile(
                mode="power_save_low_latency"
        )
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
        )

    def run(self):

        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {self.ap_mac_address}")

        if self.testcase_id == "539203" or self.testcase_id == "540498":
            self.twt_params.rx_latency = 60000
            logger().info(
                f"\nSetting the RX Latency to {self.twt_params.rx_latency} seconds...\n"
            )
            self.enable_twt()
            self.set_power_save()
            logger().info("Ping from AP backend to DUT")
            self.sl_collections.ping_with_custom_interval(
                device_ip=self.device_info["device_ip"], ping_count=5, interval=60
            )
            self.disable_twt()
            #return

        if self.testcase_id == "539204":
            self.twt_params.rx_latency = 0
            logger().info(
                f"\nSetting the RX Latency to {self.twt_params.rx_latency} seconds...\n"
            )
            self.enable_twt()
            self.set_power_save()
            self.sl_collections.ping_with_custom_interval(
                device_ip=self.device_info["device_ip"], ping_count=60, interval=1
            )
            self.disable_twt()
            #return

        if self.testcase_id == "539205" or self.testcase_id == "540499":
            self.twt_params.tx_latency = 50000
            self.enable_twt()
            self.set_power_save()
            logger().info(
                f"\nPing to DUT IP Address: {self.device_info['device_ip']} with custom interval 60 seconds....\n"
            )
            start_time = time.time()
            while (time.time() - start_time) < 80:
                self.sl_collections.ping_with_custom_interval(
                    device_ip=self.device_info["device_ip"], interval=50
                )
            logger().info(f"\n....Disabling TWT Session....\n")
            self.disable_twt()
            return

        if self.testcase_id == "539206":
            self.socket_data_transfer_obj.start_remote_socket_server(
                socket_type=SOCKET_TYPE_TCP
            )
            self.socket_data_transfer_obj.open_and_set_socket_option(
                socket_domain="AF_INET",
                socket_type="SOCK_STREAM",
                socket_protocol="IPPROTO_TCP",
                wifi_dut=self.wifi_dut,
            )
            self.twt_params.rx_latency = 60000
            self.enable_twt()
            self.twt_enable_disable_data_transfer(power_save=True)
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=0)
            return

        time.sleep(2)
        # Sniffer Validation for Power Management BIT
        power_save_filter = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.device_info["dut_mac_address"],
                da_addr=self.ap_mac_address,
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
                da_addr=self.ap_mac_address,
                filter_name="twt_requesting_sta_1",
            )
        )

        self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=twt_req_frame, packet_filter2=self.second_level_filter
        )

        self.twt_frame_info("twt_request_frame")
        twt_response_frame = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.ap_mac_address,
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

# this thread used for BLE functionality
class BleThread(ThreadBase):
    def __init__(
            self,
            wifi_dut=None,
            ble_client=None,
            ble_test_type=None,
            sl_collections=None,
            ble_scan_type=1,
            ble_scan_filter_type=0,
            ble_pairing=0,
            dev_state=8,
            service_class=None,
            conn_interval=None,
            char_path=None, char_uid=None, data=None,
            data_length=20, data_duration=60, periodic_delay=1, service_uid=None,
            address=None,
            bond_info=0,
            service_uuid=None,
            char_uuid = None,
            characteristic = None,
            ble_client_address = None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.ble_scan_type = ble_scan_type
        self.ble_pairing = ble_pairing
        self.dev_state = dev_state
        self.conn_interval = conn_interval
        self.service_class = service_class
        self.service_uid = service_uid
        self.char_path = char_path
        self.char_uid = char_uid
        self.data = data
        self.data_length = data_length
        self.data_duration = data_duration
        self.periodic_delay = periodic_delay
        self.ble_client_address = ble_client_address
        self.write_handle = None
        self.ble_scan_filter_type = ble_scan_filter_type
        self.address = address
        self.service_uuid = service_uuid
        self.char_uuid = char_uuid
        self.characteristic = characteristic
        self.bond_info = bond_info

        logger().info("Initializing BLE")
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=self.ble_pairing, bond_info=self.bond_info)
        assert (
                self.ble_dut_address is not None
        ), "Unable to fetch bluetooth address from DUT"
        logger().info(f"ble_dut_address : {self.ble_dut_address}")
        time.sleep(5)
        self.ble_client_address = None

    def add_service(self, service_uuid):
        logger().info(f"***** Configuring ble GATT service {hex(service_uuid)} in DUT *****")
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=hex(service_uuid))

    def connect_from_dut(self):
        self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                        ble_client_address=self.ble_client_address, mode="master", retries=3,
                                        ble_pairing=self.ble_pairing,
                                        dev_state=self.dev_state,
                                        max_conn_interval=self.conn_interval,
                                        min_conn_interval=self.conn_interval,
                                        timeout=30)

    def ble_disconnect(self, disconnect_from="remote"):

        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == self.dev_state, "DUT BLE device is not in connected state"

        if disconnect_from == "remote":
            logger().info(f"Initiating BLE disconnection from raspi")
            self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
        else:
            logger().info(f"Initiating BLE disconnection from DUT")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
        self.ble_client.interfaces.bluetooth.close()

    def add_characteristic(self, characteristic_uuid):
        logger().info(f"***** Configuring ble GATT characteristic {hex(characteristic_uuid)} in DUT *****")
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=hex(characteristic_uuid))

    def ble_connect(self, role="master"):

        if role == "master":
            self.sl_collections.ble_connection(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
                timeout=20, mode='master')

        else:
            logger().info("Starting DUT BLE advertising")
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            time.sleep(5)
            # Initiate BLE connection and update with 45ms interval
            self.ble_client_address = self.sl_collections.connect_ble(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                mode=self.ble_test_type,
                retries=3,
                ble_pairing=self.ble_pairing,
                min_conn_interval=self.conn_interval,
                max_conn_interval=self.conn_interval,
            )
            async_events = self.wifi_dut.interfaces.wifi.get_async_events()
            logger().info(f"async_events:{async_events}")

    def advertise_remote_device(self):
        self.ble_client_address = self.sl_collections.advertise_remote_device(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
        )

    def advertise_dut(self):
        logger().info(f"Advertising the DUT")
        self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)

    def scan_and_connect_from_remote(self):
        # Scan and Initiate BLE connection
        self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            ble_pairing=self.ble_pairing,
            dev_state=self.dev_state,
            services=self.service_class,
            max_conn_interval=self.conn_interval,
            min_conn_interval=self.conn_interval,

        )

    def scan_and_connect_from_dut(self):
        self.sl_collections.scan_and_connect_from_dut(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_client_address=self.ble_client_address,
            dev_state=self.dev_state,
            max_conn_interval=self.conn_interval,
            min_conn_interval=self.conn_interval
        )

    def check_scan_functionality_dut(self):
        self.ble_client_address = self.sl_collections.check_ble_scan_functionality(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_address=self.ble_dut_address,
            ble_scan_type=self.ble_scan_type,
            timeout=60,
            services=self.service_class
        )

    def check_adv_functionality_dut(self):
        self.ble_client_address = self.sl_collections.check_ble_advertise_functionality(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            timeout=20,
        )

    def configure_buffer_mode(self, mode=None, count=None):
        logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} ****************")
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address,
                                                                buffer_mode=mode,
                                                                buffer_count=count)
        logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} Success ****************")

    def service_discovery_on_remote(self):
        self.char_path = self.sl_collections.service_discovery_on_remote(self.ble_client,
                                                                         service_uid=self.service_uid,
                                                                         char_uid=self.char_uid)
        logger().info(f"self.char_path:{self.char_path}")

    def service_discovery_on_dut(self):
        self.write_handle = self.sl_collections.service_discovery_on_dut(ble_dut=self.wifi_dut,
                                                                         ble_client_address=self.ble_client_address,
                                                                         service_uuid=self.service_uuid,
                                                                         char_uuid=self.char_uuid,
                                                                         characteristic=self.characteristic)

    def enable_notifications_from_dut(self):
        logger().info(f"****** enabling notifications on remote****************")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=self.char_path,
                                                                                     char_uid=self.char_uid)
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address,
                                                            buffer_mode=0, buffer_count=2)
        sw = Stopwatch()
        count = 0
        logger().info(f"Send notifications from DUT")
        while sw.elapsed_sec <= self.data_duration:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(self.ble_client_address, data=self.data,
                                                                  data_address=self.address)
            time.sleep(self.periodic_delay)
            count += 1
        time.sleep(10)
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        assert len(notifications) > 0, "received data is empty"
        logger().info(f"notifications received on remote :{notifications}")
        assert len(notifications) == count, "number of notifications received are not matching with sent"
        logger().info(f"length of notifications received on remote :{len(notifications)}")
        assert notifications[0] in self.data, "failed to fetch data"

        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)

    def enable_notifications_remote(self):

        if self.write_handle:
            logger().info(f"Enabling notification on dut")
            self.wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                            handle=(self.write_handle + 1), enable_notify=1)

            tw = Stopwatch()
            Data_received_on_dut = []
            while tw.elapsed_sec < self.data_duration:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        if "rsi_ble_on_gatt_write_event_gatt" in event.event_data:
                            received_data = re.findall(r"att_value: (.*)", event.event_data)
                            Data_received_on_dut = received_data + Data_received_on_dut
                            # received_data = ord(received_data[0])
                            logger().info(f"received_data:{Data_received_on_dut}")
            assert len(Data_received_on_dut) > 0, "Notifications not received on DUT"
            self.wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                            handle=(self.write_handle + 1), enable_notify=0)

    def scan_from_remote_device(self):
        self.ble_client_address = self.sl_collections.scan_from_remote_device(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
        )

    def run(self):
        if self.ble_test_type == "advertise":
            self.check_adv_functionality_dut()

        if self.ble_test_type == "scan":
            self.check_scan_functionality_dut()

        if self.ble_test_type == "slave":
            self.ble_connect(role="slave")

        if self.ble_test_type == "master":
            self.ble_connect(role="master")

        if self.ble_test_type == "scan_from_remote_device":
            self.scan_from_remote_device()

        if self.ble_test_type == "connect_from_remote":
            self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                            ble_dut_address=self.ble_dut_address, mode="slave",
                                            retries=3, ble_pairing=self.ble_pairing, dev_state=self.dev_state,
                                            max_conn_interval=self.conn_interval,
                                            min_conn_interval=self.conn_interval,
                                            timeout=20)

        if self.ble_test_type == "scan_and_connect_from_dut":
            self.scan_and_connect_from_dut()

        if self.ble_test_type == "scan_and_connect_from_remote":
            self.scan_and_connect_from_remote()

        if self.ble_test_type == "notify_tx":
            self.enable_notifications_from_dut()

        if self.ble_test_type == "notify_rx":
            self.enable_notifications_remote()


def cleanup_ble(ble_client, ble_dut_address):
    status = ble_client.interfaces.bluetooth.get_connection_status(ble_dut_address)
    if status:
        logger().info(f"Initiating BLE disconnection from raspi")
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    ble_client.interfaces.bluetooth.close()


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
            "ble_features": Si91xBLEFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
            "wifi": {"count": 1, "stack_len": 4096, "priority": 8},
            "ble": {"count": 1, "stack_len": 4096, "priority": 8},
        },
    },
)
]

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890","dtim": 1, "standard": "gnbax", 'twt': 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_dut",wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv",
                             "disable_twt"])
def test_wifi_sdk_wifi_rx_latency_60s_ble_tx_C539203(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket
):
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        smp_enable = 1
        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
            sniffer_capture=test_name,
            testcase_id="539203",
            ping_count=ping_count,
        )
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(data), write_content=data)
        index = 1
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            ble_pairing=smp_enable,
            char_path=None, char_uid=char_uid1, data=data,
            service_uid=service_uid,
            data_length=20, data_duration=120,
            periodic_delay=1,
            conn_interval=45,
            address=address1,
        )
        twt_autoconfig_obj.join_to_ap()
        # Create Custom services on DUT
        # Create Custom services, attributes, values

        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        ble_obj.advertise_dut()
        ble_obj.scan_and_connect_from_remote()
        ble_obj.service_discovery_on_remote()

        ble_obj.start()
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        time.sleep(2)
        wifi_dut.interfaces.wifi.memory_free(address1)
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")

        #Close the BLE of Raspberry Pi
        ble_client.interfaces.bluetooth.close()
        if ble_obj:
            # Clean up the BLE based on the device state
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890","dtim": 1, "standard": "gnbax", 'twt': 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_dut",wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv",
                             "disable_twt"])
def test_wifi_sdk_wifi_rx_latency_0_ble_tx_C539204(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket
):

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        smp_enable = 1

        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            sniffer_capture=test_name,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
            testcase_id="539204",
            ping_count=ping_count,
        )

        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(data), write_content=data)
        index = 1
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            ble_pairing=smp_enable,
            char_path=None, char_uid=char_uid1, data=data,
            service_uid=service_uid,
            data_length=20, data_duration=60,
            periodic_delay=1,
            conn_interval=45,
            address=address1,
        )
        twt_autoconfig_obj.join_to_ap()
        # Create Custom services on DUT
        # Create Custom services, attributes, values
        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        ble_obj.advertise_dut()
        ble_obj.scan_and_connect_from_remote()
        ble_obj.service_discovery_on_remote()
        ble_obj.start()
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        time.sleep(2)
        wifi_dut.interfaces.wifi.memory_free(address1)
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Close the BLE of Raspberry Pi
        ble_client.interfaces.bluetooth.close()
        if ble_obj:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890","dtim": 1, "standard": "gnbax", 'twt': 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_dut",wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv",
                             "disable_twt"])
def test_wifi_sdk_wifi_tx_latency_50s_ble_rx_C539205(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket
):

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        smp_enable = 1

        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            sniffer_capture=test_name,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
            testcase_id="539205",
            ping_count=ping_count,
        )
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=8,
            data_duration=30,
            service_class=["HeartRateService"],
            ble_pairing=smp_enable,
            bond_info=1,
            conn_interval=250,
            service_uuid=HeartRateService.UUID,
            char_uuid=HeartRateMeasurementCharacterstic.HR_Measure_UUID,
            characteristic=HeartRateMeasurementCharacterstic
        )

        ble_obj.check_scan_functionality_dut()
        twt_autoconfig_obj.join_to_ap()
        logger().info("Initiating stop scan from dut")
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        ble_obj.connect_from_dut()
        ble_obj.service_discovery_on_dut()
        ble_obj.start()
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Close the BLE of Raspberry Pi
        ble_client.interfaces.bluetooth.close()

        if ble_obj:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.skip("Test case development is in progress")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890","dtim": 1, "standard": "gnbax"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_dut",wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv",
                             "disable_twt"])
def test_wifi_sdk_ble_scan_adv_behaviour_twt_enable_traffic_enable_ps_enable_twt_disable_traffic_disable_ps_disable_c539206(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        sl_collections,
        wifi_client,
        sniffer_filter,
        remote_socket
):
    """
        Test Steps:
            1. Advertise the DUT
            2. Start BLE scanning from Remote device
            3. Advertise the Remote device
            4. Start BLE scanning from DUT
            5. Join to the AP(Scan, connect, ping before power save)
            6. Enable TWT
            7. Enable Power Save
            8. Send data over socket
            9. Disable TWT
            10. Disable Power Save
            11. Send data over socket
    """
    test_name = request.node.name
    try:

        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            remote_socket=remote_socket,
            sniffer_capture=test_name,
            testcase_id="539206",
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
        )
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
        )
        ble_obj.check_adv_functionality_dut()
        ble_client.interfaces.bluetooth.close()
        ble_obj.check_scan_functionality_dut()
        twt_autoconfig_obj.join_to_ap()
        twt_autoconfig_obj.start()
        twt_autoconfig_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info("Finally")
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Close the BLE of Raspberry Pi
        ble_client.interfaces.bluetooth.close()
        if ble_obj:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890","dtim": 1, "standard": "gnbax", 'twt': 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_dut",wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv",
                             "disable_twt"])
def test_wifi_sdk_wifi_rx_latency_60s_ble_slave_conn_discon_C540498(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket
):

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        smp_enable = 1

        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
            remote_socket=remote_socket,
            sniffer_capture=test_name,
            testcase_id="540498",
            ping_count=ping_count,
        )

        # BLE Thread
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_interval=30,
            dev_state=8,
            ble_pairing=smp_enable,
            bond_info=1
        )

        twt_autoconfig_obj.join_to_ap()
        twt_autoconfig_obj.start()
        # Start BLE advertise followed by Raspberry Pi connection with DUT
        for i in range(0,3):
            ble_obj.advertise_dut()
            ble_obj.scan_and_connect_from_remote()
            time.sleep(60)
            ble_obj.ble_disconnect(disconnect_from="dut")
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            time.sleep(2)
        twt_autoconfig_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Close the BLE of Raspberry Pi
        ble_client.interfaces.bluetooth.close()

        if ble_obj:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890","dtim": 1, "standard": "gnbax", 'twt': 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_dut",wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv",
                             "disable_twt"])
def test_wifi_sdk_wifi_tx_latency_50s_ble_slave_conn_discon_C540499(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket
):

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        smp_enable = 1

        twt_autoconfig_obj = TWT_AUTOCONFIG(
            wifi_dut=wifi_dut,
            wifi_sniffer=wifi_sniffer,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            wifi_client=wifi_client,
            remote_socket=remote_socket,
            sniffer_capture=test_name,
            testcase_id="540499",
            ping_count=ping_count,
        )

        # BLE Thread
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_interval=30,
            dev_state=8,
            ble_pairing=smp_enable,
            bond_info=1
        )

        twt_autoconfig_obj.join_to_ap()
        twt_autoconfig_obj.start()
        # Start BLE advertise followed by Raspberry Pi connection with DUT
        for i in range(0, 3):
            ble_obj.advertise_dut()
            ble_obj.scan_and_connect_from_remote()
            time.sleep(60)
            ble_obj.ble_disconnect(disconnect_from="dut")
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            time.sleep(2)
        twt_autoconfig_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:(
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex))

    finally:
        logger().info("Finally")
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Close the BLE of Raspberry Pi
        ble_client.interfaces.bluetooth.close()

        if ble_obj:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)