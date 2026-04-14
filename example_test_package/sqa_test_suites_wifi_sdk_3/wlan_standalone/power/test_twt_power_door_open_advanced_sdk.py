import pytest
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.stopwatch import Stopwatch
from utf.utils import print_dict
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xOperatingMode,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xJoinFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xRegion,
    Si91xAwsQos,
    Si91xCertificateType,
    Si91xCertIdentifier,
    Si91xRegionCode,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xModuleType,
)
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from random import randint
from utf.utils.thread_base import ThreadBase
import os
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.power_meter.nrf_ppk2.nrf_power_profiler_mp import NRFPowerProfiler
from AWSIoTPythonSDK.core.protocol.internal.clients import ClientStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import string
import random
from retry import retry
from utf import UtfDatabaseProperties, TestUserPropertiesSource, UtfTestReport, TransformFileProperties


def logger():
    return get_logger(__name__)


def text_generator(size=2000):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)


class device_scan_result:
    def check_for_devices_in_scanned_results(self, ble_client, bt_dut_address, adv_data):
        sw = Stopwatch()
        previously_found_devices = {}
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            if previously_found_devices != found_devices:
                logger().info(f"BLE scan results :{found_devices}")
                previously_found_devices = found_devices

            if (
                    bt_dut_address in found_devices
                    and found_devices[bt_dut_address] == adv_data
            ):
                return True
        return False


class Power_Device:

    def __init__(self) -> None:
        pass

    def power_measurement(power_device=None, power_meter=None, dtim=None, capture_time=60):

        if power_device == "keysight_benchvue_power_analyzer_win_wcf":
            power_obj = power_number_output(power_meter=power_meter, dtim=dtim, capture_time=capture_time)
        elif power_device == "nrf_ppk2_device":
            power_obj = ppk_power_number_output(power_meter=power_meter)
        power_obj.get_power_value()


class power_number_output():
    def __init__(self, power_meter=None, dtim=None, capture_time=60):
        super().__init__()
        self.power_meter = power_meter
        self.dtim = dtim
        self.capture_time = capture_time

    def __print_throughput(self, throughput: dict):
        if throughput is not None:
            print_dict("##     ", throughput)

    def get_power_value(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        if self.dtim:
            # Init power meter by specifying module name as datalogger or scope
            logger().info(f"initiating power meter wih dtim")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log_{self.dtim}",
                                                                     data_log_stop_after_elapsed_time=self.capture_time)
        else:
            logger().info(f"initiating power meter")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log",
                                                                     data_log_stop_after_elapsed_time=self.capture_time)
        # Init power meter module

        self.power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
        # set power meter out put channels
        logger().info(f"setting output channels")

        if dut == "si917_ncp_sl_wifi":
            self.power_meter.interfaces.power_meter.set_output_channels_settings(
                [{"channel": "1", "emulation_mode": "Current Measure", "trace_current": True, "trace_voltage": False,
                  "trace_power": False}])

        else:
            self.power_meter.interfaces.power_meter.set_output_channels_settings([{"channel": "1",
                                                                                   "emulation_mode": "2 Quadrant Power Supply",
                                                                                   "voltage": "3.3000",
                                                                                   "current_limit": "1.00000",
                                                                                   "voltage_slew": "MAX",
                                                                                   "voltage_meter_range": "Auto",
                                                                                   "current_meter_range": "Auto",
                                                                                   "trace_voltage": False,
                                                                                   "trace_current": True,
                                                                                   "trace_power": False}])
        time.sleep(10)
        # start capture power meter datalog/scope
        logger().info(f"starting power meter capture")
        self.power_meter.interfaces.power_meter.start_capture()

        # Parse result as throughput object
        logger().info(f"parsing output result")
        parsed_result = self.power_meter.interfaces.power_meter.power_meter_module.process_output(
            self.power_meter.interfaces.power_meter.results)
        self.__print_throughput(parsed_result)
        assert parsed_result["Output"] is not None


class ppk_power_number_output():
    def __init__(self, power_meter=None):
        super().__init__()
        self.power_meter = power_meter

    def __print_throughput(self, throughput: dict):
        if throughput is not None:
            print_dict("##     ", throughput)

    def get_power_value(self):
        # Start Capture
        logger().info("Starting PPK capture")
        self.power_meter.interfaces.power_meter.start_capture()
        # Process Output
        file_size = os.path.getsize(self.power_meter.interfaces.power_meter.capture_file)
        assert file_size > 0
        parsed_result = self.power_meter.interfaces.power_meter.process_output()
        self.__print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        time.sleep(10)


class WifiSockthread(ThreadBase):

    def __init__(self, remote_socket=None, wifi_dut=None, wifi_access_point=None, device2_ip=None, m4_deep_sleep=False,
                 tcp_ka_time=240, send_data=False, send_ka=False, door_scenario=None, camera_scenario=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.device2_ip = device2_ip
        self.remote_socket = remote_socket
        self.m4_deep_sleep = m4_deep_sleep
        self.tcp_ka_time = tcp_ka_time
        self.send_data = send_data
        self.send_ka = send_ka
        self.door_scenario = door_scenario
        self.camera_scenario = camera_scenario

    def run(self):
        if self.door_scenario:
            logger().info("Door scenario starts")
            data_size = 11
            no_of_iterations = 30
            device2_ip = self.device2_ip
            self.remote_socket.interfaces.socket.time_limit = 3600

            server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
            logger().info(f"Remote device ip :{server_ip}")
            server_port = self.remote_socket.interfaces.socket.server_port
            logger().info(f"Starting tcp server remotely at port number 5001")
            self.remote_socket.interfaces.socket.start_server()

            # DUT opens tcp client socket
            sock_id = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET",
                                                           stream_type="SOCK_STREAM",
                                                           protocol="IPPROTO_TCP")
            assert sock_id == 0, f"socket id received is wrong, expected is 0"
            logger().info(f"socket id received is {sock_id} which is expected")

            # Socket binds at (device2_ip, 5001) in DUT
            self.wifi_dut.interfaces.wifi.bind(socket_fd=sock_id,
                                               device_ip=device2_ip,
                                               server_port=server_port)
            # tcp socket opened in DUT connects to the tcp server
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock_id,
                                                           server_ip=server_ip,
                                                           server_port=server_port)
            if self.send_ka:
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock_id,
                                                              option_level='SOL_SOCKET',
                                                              option_name='SO_KEEPALIVE',
                                                              option_val=str(self.tcp_ka_time))

            elif self.send_data:
                for i in range(1, no_of_iterations):
                    data = "tcpdatasend"
                    self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock_id,
                                                                data=data)
                    time.sleep(1)
                    data = self.remote_socket.interfaces.socket.recv_data_tcp(len(data))
                    logger().info(f"Received data: {data}")

            time.sleep(2)
            if not self.m4_deep_sleep:
                self.remote_socket.interfaces.socket.socket_close_indication(1)
                logger().info("closing the remote socket ")

        if self.camera_scenario:
            logger().info("Door scenario starts")
            no_of_iterations = 10
            device2_ip = self.device2_ip
            self.remote_socket.interfaces.socket.time_limit = 3600

            server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
            logger().info(f"Remote device ip :{server_ip}")
            server_port = self.remote_socket.interfaces.socket.server_port
            logger().info(f"Starting UDP server remotely at port number 5001")
            socket_type = 'SOCKET_TYPE_UDP'
            self.remote_socket.interfaces.socket.start_server(port=server_port, socket_type=socket_type)
            sock_id = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET",
                                                           stream_type="SOCK_DGRAM",
                                                           protocol="IPPROTO_UDP")
            assert sock_id == 0, f"socket id received is wrong, expected is 0"
            logger().info(f"socket id received is {sock_id} which is expected")

            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
                socket_fd=sock_id, option_name="SO_KEEPALIVE", option_val="240"
            )
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                socket_fd=sock_id,
                server_ip=server_ip,
                server_port=server_port,
                timeout=30,
            )
            if self.send_ka:
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock_id,
                                                              option_level='SOL_SOCKET',
                                                              option_name='SO_KEEPALIVE',
                                                              option_val=str(self.tcp_ka_time))

            elif self.send_data:
                sw = Stopwatch()
                duration = 60
                while sw.elapsed_sec < duration:
                    data = "Hello_from"
                    self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock_id, data=data, higher_data_len=0)
                    time.sleep(1)
                    data = self.remote_socket.interfaces.socket.recv_data_udp(len(data))
                    logger().info(f"Received data: {data}")

            time.sleep(2)
            if not self.m4_deep_sleep:
                self.remote_socket.interfaces.socket.socket_close_indication(1)


class WlanThread(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None, aws_conn=None,
                 dtim=10, listen_interval=0, without_ip=False, topic=None, messages=None, qos=Si91xAwsQos.QOS1,
                 listen_int_1=None, listen_int_05=None, rx_latency_1=None, rx_latency_2=None, rx_latency_5=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.dtim = dtim
        self.listen_interval = listen_interval
        self.device_ip = None
        self.without_ip = without_ip
        self.aws_conn = aws_conn
        self.topic = topic
        self.qos = qos
        self.messages = messages
        self.listen_int_1 = listen_int_1
        self.listen_int_05 = listen_int_05
        self.rx_latency_1 = rx_latency_1
        self.rx_latency_2 = rx_latency_2
        self.rx_latency_5 = rx_latency_5

    def run(self):
        logger().info(f"Scanning and Connecting to Access Point")
        if self.listen_int_1:
            logger().info("Setting the listen for 1 sec")
            listen_interval = 1000
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
        if self.listen_int_05:
            logger().info("Setting the listen for 0.5 sec")
            listen_interval2 = 500
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval2)
        dictionary = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            listen_interval=self.listen_interval,
            power_save=False,
            ip_config_disable=self.without_ip,
            retry_count=3
        )
        if not self.without_ip:
            self.device_ip = dictionary['device_ip']
        if self.rx_latency_1:
            logger().info("setting the twt parameters for rx_latency_1")
            self.wifi_dut.interfaces.wifi.twt_auto_config(twt_enable=1, average_tx_throughput=1000, tx_latency=0,
                                                          rx_latency=10000, device_average_throughput=20000,
                                                          estimated_extra_wake_duration_percent=0,
                                                          twt_tolerable_deviation=10, default_wake_interval_ms=1024,
                                                          default_minimum_wake_duration_ms=8, beacon_wake_up_count_after_sp=2)
        if self.rx_latency_2:
            logger().info("setting the twt parameters for rx_latency_2")
            self.wifi_dut.interfaces.wifi.twt_auto_config(twt_enable=1, average_tx_throughput=1000, tx_latency=0,
                                                          rx_latency=20000, device_average_throughput=20000,
                                                          estimated_extra_wake_duration_percent=0,
                                                          twt_tolerable_deviation=10, default_wake_interval_ms=1024,
                                                          default_minimum_wake_duration_ms=8,
                                                          beacon_wake_up_count_after_sp=2)
        if self.rx_latency_5:
            logger().info("setting the twt parameters for rx_latency_5")
            self.wifi_dut.interfaces.wifi.twt_auto_config(twt_enable=1, average_tx_throughput=1000, tx_latency=0,
                                                          rx_latency=50000, device_average_throughput=20000,
                                                          estimated_extra_wake_duration_percent=0,
                                                          twt_tolerable_deviation=10, default_wake_interval_ms=1024,
                                                          default_minimum_wake_duration_ms=8,
                                                          beacon_wake_up_count_after_sp=2)

    def getter(self):
        return self.device_ip


class M4_Sleep_Thread(ThreadBase):
    def __init__(self, wifi_dut=None, m4_sleep_time=180000, deep_sleep_without_ret=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.m4_sleep_time = m4_sleep_time
        self.deep_sleep_without_ret = deep_sleep_without_ret

    def run(self):
        logger().info(f"Enabling M4 power save")
        if self.deep_sleep_without_ret:
            self.wifi_dut.interfaces.wifi.m4_power_manager_deep_sleep(state=0,
                                                                      sleep_time=self.m4_sleep_time,
                                                                      timeout=400
                                                                      )
        else:
            self.wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=self.m4_sleep_time, timeout=250)


class Power_Measurement_Thread(ThreadBase, Power_Device):

    def __init__(self, power_meter=None, capture_time=60):
        super().__init__()
        Power_Device().__init__()
        self.power_meter = power_meter
        self.capture_time = capture_time

    def run(self):
        logger().info(f"Starting Power Capture")
        self.power_device = UtfConfig.instance().defaults.get("power_meter", {})
        Power_Device.power_measurement(power_device=self.power_device, power_meter=self.power_meter,
                                       capture_time=self.capture_time)


class StandBy_Associated(ThreadBase):
    def __init__(self, dtim=None, wifi_dut=None, wifi_access_point=None, sl_collections=None, power_meter=None,
                 deep_sleep=False, dtim_aligned_type=1,
                 remote_socket=None, send_data=False, capture_time=60, m4_sleep_time=100000, bcast_filter=True,
                 tcp_ka_time=240, send_ka=False):
        self.dtim = dtim
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.wifi_access_point = wifi_access_point
        self.power_meter = power_meter
        self.deep_sleep = deep_sleep
        self.remote_socket = remote_socket
        self.send_data = send_data
        self.send_ka = send_ka
        self.capture_time = capture_time
        self.m4_sleep_time = m4_sleep_time
        self.bcast_filter = bcast_filter
        self.tcp_ka_time = tcp_ka_time
        self.dtim_aligned_type = dtim_aligned_type

    def run(self):
        logger().info(f"M4-TA secure handshake")
        self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

        time.sleep(2)

        self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )
        wlan_obj = WlanThread(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, dtim=self.dtim,
                              sl_collections=self.sl_collections)
        if self.deep_sleep:
            m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time,
                                     deep_sleep_without_ret=True)
        else:
            m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time)
        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter, capture_time=self.capture_time)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        if self.send_data or self.send_ka:
            device2_ip = wlan_obj.getter()
            wifisock_obj = WifiSockthread(remote_socket=self.remote_socket, wifi_dut=self.wifi_dut,
                                          wifi_access_point=self.wifi_access_point, device2_ip=device2_ip,
                                          m4_deep_sleep=True, tcp_ka_time=self.tcp_ka_time, send_ka=self.send_ka,
                                          send_data=self.send_data)
            wifisock_obj.start()

        time.sleep(2)

        if self.bcast_filter:
            logger().info(f"Setting filter broadcast command")
            self.wifi_dut.interfaces.wifi.set_filter_broadcast()

        time.sleep(2)

        logger().info(f"Enabling TA power save")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save",
                                                              dtim_aligned_type=self.dtim_aligned_type)
        time.sleep(2)

        m4_obj.start()
        time.sleep(2)
        pm_obj.start()
        pm_obj.wait_for_exit()
        m4_obj.wait_for_exit()

        if self.send_data:
            wifisock_obj.wait_for_exit()

        time.sleep(10)


# ********************************************************************************************************************

pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]


# ********************************************************************************************************************

@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode, # | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C166149')
def test_standby_power_twt_enable_door_rx_latency_1_C166149(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                 sl_collections, request, remote_socket, performance_data,
                                                 custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    # wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
    time.sleep(2)
    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections, listen_int_1=True, rx_latency_1=True)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    # wifi_dut.interfaces.wifi.twt_auto_config()
    device2_ip = wlan_obj.getter()

    wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   device2_ip=device2_ip, m4_deep_sleep=False, send_data=True, door_scenario=True)
    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()
    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)
    wifi_sock_obj.start()
    wifi_sock_obj.wait_for_exit()
    m4_obj.start()
    pm_obj.start()
    time.sleep(125)
    m4_obj.wait_for_exit()
    pm_obj.wait_for_exit()
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name,
                                                             opn=opn,
                                                             build_number=build_number,
                                                             memory_configuration="test_352K_M4SS_320K",
                                                             parsed_result=parsed_result["Output"],
                                                             file_path=performance_file_root_dir,
                                                             file_name=perf_file_name
                                                             )

    time.sleep(10)


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode, # | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C166150')
def test_standby_power_twt_enable_door_rx_latency_2_C166150(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                 sl_collections, request, remote_socket, performance_data,
                                                 custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    # wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
    time.sleep(2)
    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections, listen_int_1=True, rx_latency_2=True)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    wifi_dut.interfaces.wifi.twt_auto_config()
    device2_ip = wlan_obj.getter()

    wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   device2_ip=device2_ip, m4_deep_sleep=False, send_data=True, door_scenario=True)
    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()
    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)
    wifi_sock_obj.start()
    wifi_sock_obj.wait_for_exit()
    m4_obj.start()
    pm_obj.start()
    time.sleep(125)
    m4_obj.wait_for_exit()
    pm_obj.wait_for_exit()
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name,
                                                             opn=opn,
                                                             build_number=build_number,
                                                             memory_configuration="test_352K_M4SS_320K",
                                                             parsed_result=parsed_result["Output"],
                                                             file_path=performance_file_root_dir,
                                                             file_name=perf_file_name
                                                             )

    time.sleep(10)

@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode, # | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C166151')
def test_standby_power_twt_enable_door_rx_latency_5_C166151(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                 sl_collections, request, remote_socket, performance_data,
                                                 custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    # wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
    time.sleep(2)
    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections, listen_int_1=True, rx_latency_5=True)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    wifi_dut.interfaces.wifi.twt_auto_config()
    device2_ip = wlan_obj.getter()

    wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   device2_ip=device2_ip, m4_deep_sleep=False, send_data=True, door_scenario=True)
    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()
    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)
    wifi_sock_obj.start()
    wifi_sock_obj.wait_for_exit()
    m4_obj.start()
    pm_obj.start()
    time.sleep(125)
    m4_obj.wait_for_exit()
    pm_obj.wait_for_exit()
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name,
                                                             opn=opn,
                                                             build_number=build_number,
                                                             memory_configuration="test_352K_M4SS_320K",
                                                             parsed_result=parsed_result["Output"],
                                                             file_path=performance_file_root_dir,
                                                             file_name=perf_file_name
                                                             )

    time.sleep(10)


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode, # | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C166152')
def test_standby_power_twt_enable_door_rx_latency1_500_C166152(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                 sl_collections, request, remote_socket, performance_data,
                                                 custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    # wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
    time.sleep(2)
    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections, listen_int_05=True, rx_latency_1=True)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    # wifi_dut.interfaces.wifi.twt_auto_config()
    device2_ip = wlan_obj.getter()

    wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   device2_ip=device2_ip, m4_deep_sleep=False, send_data=True, door_scenario=True)
    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()
    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)
    wifi_sock_obj.start()
    wifi_sock_obj.wait_for_exit()
    m4_obj.start()
    pm_obj.start()
    time.sleep(125)
    m4_obj.wait_for_exit()
    pm_obj.wait_for_exit()
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name,
                                                             opn=opn,
                                                             build_number=build_number,
                                                             memory_configuration="test_352K_M4SS_320K",
                                                             parsed_result=parsed_result["Output"],
                                                             file_path=performance_file_root_dir,
                                                             file_name=perf_file_name
                                                             )

    time.sleep(10)


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode, # | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C166153')
def test_standby_power_twt_enable_door_rx_latency2_500_C166153(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                 sl_collections, request, remote_socket, performance_data,
                                                 custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    # wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
    time.sleep(2)
    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections, listen_int_05=True, rx_latency_2=True)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    wifi_dut.interfaces.wifi.twt_auto_config()
    device2_ip = wlan_obj.getter()

    wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   device2_ip=device2_ip, m4_deep_sleep=False, send_data=True, door_scenario=True)
    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()
    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)
    wifi_sock_obj.start()
    wifi_sock_obj.wait_for_exit()
    m4_obj.start()
    pm_obj.start()
    time.sleep(125)
    m4_obj.wait_for_exit()
    pm_obj.wait_for_exit()
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name,
                                                             opn=opn,
                                                             build_number=build_number,
                                                             memory_configuration="test_352K_M4SS_320K",
                                                             parsed_result=parsed_result["Output"],
                                                             file_path=performance_file_root_dir,
                                                             file_name=perf_file_name
                                                             )

    time.sleep(10)

@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode, # | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C166154')
def test_standby_power_twt_enable_door_rx_latency5_500_C166154(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                 sl_collections, request, remote_socket, performance_data,
                                                 custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    # wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
    time.sleep(2)
    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections, listen_int_05=True, rx_latency_5=True)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    wifi_dut.interfaces.wifi.twt_auto_config()
    device2_ip = wlan_obj.getter()

    wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   device2_ip=device2_ip, m4_deep_sleep=False, send_data=True, door_scenario=True)
    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()
    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)
    wifi_sock_obj.start()
    wifi_sock_obj.wait_for_exit()
    m4_obj.start()
    pm_obj.start()
    time.sleep(125)
    m4_obj.wait_for_exit()
    pm_obj.wait_for_exit()
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name,
                                                             opn=opn,
                                                             build_number=build_number,
                                                             memory_configuration="test_352K_M4SS_320K",
                                                             parsed_result=parsed_result["Output"],
                                                             file_path=performance_file_root_dir,
                                                             file_name=perf_file_name
                                                             )

    time.sleep(10)


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode, # | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C166155')
def test_standby_power_twt_enable_camera_rx_latency_1_C166155(power_meter, wifi_access_point, wifi_dut,
                                                 sl_collections, request, remote_socket, performance_data,
                                                 custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    # wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
    time.sleep(2)
    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections, listen_int_1=True, rx_latency_1=True)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    # wifi_dut.interfaces.wifi.twt_auto_config()
    device2_ip = wlan_obj.getter()

    wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   device2_ip=device2_ip, m4_deep_sleep=False, send_data=True, camera_scenario=True)
    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()
    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)
    wifi_sock_obj.start()
    wifi_sock_obj.wait_for_exit()
    m4_obj.start()
    pm_obj.start()
    time.sleep(125)
    m4_obj.wait_for_exit()
    pm_obj.wait_for_exit()
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name,
                                                             opn=opn,
                                                             build_number=build_number,
                                                             memory_configuration="test_352K_M4SS_320K",
                                                             parsed_result=parsed_result["Output"],
                                                             file_path=performance_file_root_dir,
                                                             file_name=perf_file_name
                                                             )

    time.sleep(10)


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode, # | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C166156')
def test_standby_power_twt_enable_camera_rx_latency_2_C166156(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                 sl_collections, request, remote_socket, performance_data,
                                                 custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    # wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
    time.sleep(2)
    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections, listen_int_1=True, rx_latency_2=True)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    wifi_dut.interfaces.wifi.twt_auto_config()
    device2_ip = wlan_obj.getter()

    wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   device2_ip=device2_ip, m4_deep_sleep=False, send_data=True, camera_scenario=True)
    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()
    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)
    wifi_sock_obj.start()
    wifi_sock_obj.wait_for_exit()
    m4_obj.start()
    pm_obj.start()
    time.sleep(125)
    m4_obj.wait_for_exit()
    pm_obj.wait_for_exit()
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name,
                                                             opn=opn,
                                                             build_number=build_number,
                                                             memory_configuration="test_352K_M4SS_320K",
                                                             parsed_result=parsed_result["Output"],
                                                             file_path=performance_file_root_dir,
                                                             file_name=perf_file_name
                                                             )

    time.sleep(10)

@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode, # | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C166157')
def test_standby_power_twt_enable_camera_rx_latency_5_C166157(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                 sl_collections, request, remote_socket, performance_data,
                                                 custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    # wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
    time.sleep(2)
    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections, listen_int_1=True, rx_latency_5=True)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    wifi_dut.interfaces.wifi.twt_auto_config()
    device2_ip = wlan_obj.getter()

    wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   device2_ip=device2_ip, m4_deep_sleep=False, send_data=True, camera_scenario=True)
    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()
    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)
    wifi_sock_obj.start()
    wifi_sock_obj.wait_for_exit()
    m4_obj.start()
    pm_obj.start()
    time.sleep(125)
    m4_obj.wait_for_exit()
    pm_obj.wait_for_exit()
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name,
                                                             opn=opn,
                                                             build_number=build_number,
                                                             memory_configuration="test_352K_M4SS_320K",
                                                             parsed_result=parsed_result["Output"],
                                                             file_path=performance_file_root_dir,
                                                             file_name=perf_file_name
                                                             )

    time.sleep(10)


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode, # | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C166158')
def test_standby_power_twt_enable_camera_rx_latency1_500_C166158(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                 sl_collections, request, remote_socket, performance_data,
                                                 custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    # wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
    time.sleep(2)
    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections, listen_int_05=True, rx_latency_1=True)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    # wifi_dut.interfaces.wifi.twt_auto_config()
    device2_ip = wlan_obj.getter()

    wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   device2_ip=device2_ip, m4_deep_sleep=False, send_data=True, camera_scenario=True)
    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()
    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)
    wifi_sock_obj.start()
    wifi_sock_obj.wait_for_exit()
    m4_obj.start()
    pm_obj.start()
    time.sleep(125)
    m4_obj.wait_for_exit()
    pm_obj.wait_for_exit()
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name,
                                                             opn=opn,
                                                             build_number=build_number,
                                                             memory_configuration="test_352K_M4SS_320K",
                                                             parsed_result=parsed_result["Output"],
                                                             file_path=performance_file_root_dir,
                                                             file_name=perf_file_name
                                                             )

    time.sleep(10)


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode, # | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C166159')
def test_standby_power_twt_enable_camera_rx_latency2_500_C166159(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                 sl_collections, request, remote_socket, performance_data,
                                                 custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    # wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
    time.sleep(2)
    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections, listen_int_05=True, rx_latency_2=True)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    wifi_dut.interfaces.wifi.twt_auto_config()
    device2_ip = wlan_obj.getter()

    wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   device2_ip=device2_ip, m4_deep_sleep=False, send_data=True, camera_scenario=True)
    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()
    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)
    wifi_sock_obj.start()
    wifi_sock_obj.wait_for_exit()
    m4_obj.start()
    pm_obj.start()
    time.sleep(125)
    m4_obj.wait_for_exit()
    pm_obj.wait_for_exit()
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name,
                                                             opn=opn,
                                                             build_number=build_number,
                                                             memory_configuration="test_352K_M4SS_320K",
                                                             parsed_result=parsed_result["Output"],
                                                             file_path=performance_file_root_dir,
                                                             file_name=perf_file_name
                                                             )

    time.sleep(10)

@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode, # | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C166160')
def test_standby_power_twt_enable_camera_rx_latency5_500_C166160(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                 sl_collections, request, remote_socket, performance_data,
                                                 custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    # wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
    time.sleep(2)
    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections, listen_int_05=True, rx_latency_5=True)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()
    wifi_dut.interfaces.wifi.twt_auto_config()
    device2_ip = wlan_obj.getter()

    wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   device2_ip=device2_ip, m4_deep_sleep=False, send_data=True, camera_scenario=True)
    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()
    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)
    wifi_sock_obj.start()
    wifi_sock_obj.wait_for_exit()
    m4_obj.start()
    pm_obj.start()
    time.sleep(125)
    m4_obj.wait_for_exit()
    pm_obj.wait_for_exit()
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name,
                                                             opn=opn,
                                                             build_number=build_number,
                                                             memory_configuration="test_352K_M4SS_320K",
                                                             parsed_result=parsed_result["Output"],
                                                             file_path=performance_file_root_dir,
                                                             file_name=perf_file_name
                                                             )

    time.sleep(10)