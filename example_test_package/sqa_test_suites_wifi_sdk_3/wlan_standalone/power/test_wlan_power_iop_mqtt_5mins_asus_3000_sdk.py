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
from utf import UtfDatabaseProperties, TestUserPropertiesSource, UtfTestReport, TransformFileProperties


def logger():
    return get_logger(__name__)


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
            self.power_meter.interfaces.power_meter.set_output_channels_settings([{"channel": "3",
                                                                                   "emulation_mode": "2 Quadrant Power Supply",
                                                                                   "voltage": "3.3000",
                                                                                   "current_limit": "1.00000",
                                                                                   "voltage_slew": "MAX",
                                                                                   "voltage_meter_range": "Auto",
                                                                                   "current_meter_range": "Auto",
                                                                                   "trace_current": True,
                                                                                   "trace_power": True}])
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
                 tcp_ka_time=240, send_data=False, send_ka=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.device2_ip = device2_ip
        self.remote_socket = remote_socket
        self.m4_deep_sleep = m4_deep_sleep
        self.tcp_ka_time = tcp_ka_time
        self.send_data = send_data
        self.send_ka = send_ka

    def run(self):
        data_size = 42
        data = "tcpdatastartedtcpdatastartedtcpdatastarted"
        no_of_iterations = 2
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
                self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock_id,
                                                            data=data)
                data = self.remote_socket.interfaces.socket.recv_data_tcp(data_size)
                time.sleep(self.tcp_ka_time)

        time.sleep(2)
        if not self.m4_deep_sleep:
            result = self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            assert b"success" in result, "unable to close opened tcp socket"
        self.remote_socket.interfaces.socket.socket_close_indication(1)


class WlanThread(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None,
                 dtim=10, listen_interval=0, without_dtim=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.dtim = dtim
        self.listen_interval = listen_interval
        self.device_ip = None
        self.without_dtim = without_dtim

    def run(self):
        if self.without_dtim:
            logger().info("Continued without DTIM")
        else:
            logger().info(f"Configuring Access Point with dtim : {self.dtim}")
            self.wifi_access_point.interfaces.wifi.start_ap(dtim=self.dtim)

        logger().info(f"Scanning and Connecting to Access Point")
        dictionary = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            listen_interval=self.listen_interval,
            power_save=False,
            retry_count=3
        )
        self.device_ip = dictionary['device_ip']

    def getter(self):
        return self.device_ip


class M4_Sleep_Thread(ThreadBase):
    def __init__(self, wifi_dut=None, m4_sleep_time=100000, deep_sleep_without_ret=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.m4_sleep_time = m4_sleep_time
        self.deep_sleep_without_ret = deep_sleep_without_ret

    def run(self):
        logger().info(f"Enabling M4 power save")
        if self.deep_sleep_without_ret:
            self.wifi_dut.interfaces.wifi.m4_power_manager_deep_sleep(state=0,
                                                                      sleep_time=self.m4_sleep_time)
        else:
            self.wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=self.m4_sleep_time, timeout=360)
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.leave()
        logger().info(f'DUT is leaving the AP')


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
                 deep_sleep=False, dtim_aligned_type=1, remote_socket=None, send_data=False, capture_time=60,
                 m4_sleep_time=120000, bcast_filter=True, tcp_ka_time=240, send_ka=False, listen_case=False,
                 mqtt_ka_enable=None, mqtt_server=None):

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
        self.listen_case = listen_case
        self.mqtt_ka_enable = mqtt_ka_enable
        self.mqtt_server = mqtt_server

    def run(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")

        if dut != "si917_ncp_sl_wifi":
            logger().info(f"M4-TA secure handshake")
            self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

        time.sleep(2)
        if self.mqtt_ka_enable:
            listen_interval = 1000
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
        else:
            listen_interval = 1000
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
        if self.mqtt_ka_enable:
            wlan_obj = WlanThread(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                  sl_collections=self.sl_collections, without_dtim=True)
        else:
            wlan_obj = WlanThread(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                  sl_collections=self.sl_collections, without_dtim=True)
        if dut != "si917_ncp_sl_wifi":
            if self.deep_sleep:
                m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time,
                                         deep_sleep_without_ret=True)
            else:
                m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time)
        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter, capture_time=self.capture_time)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        if self.mqtt_ka_enable:
            logger().info("Setting the MQTT Keep-Alive for 55")
            self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
            self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client_power",
                                                                            keep_alive_interval=55)
            logger().info("DUT connecting to MQTT server")
            self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)

            time.sleep(5)

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

        if self.mqtt_ka_enable:
            logger().info(f"Enabling TA power save")
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save",
                                                                  listen_interval=1)
            time.sleep(2)

        logger().info(f"Enabling TA power save")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save",
                                                              listen_interval=1)
        time.sleep(2)

        if dut != "si917_ncp_sl_wifi":
            m4_obj.start()
            time.sleep(2)

        pm_obj.start()

        if self.listen_case:
            time.sleep(35)
            self.wifi_access_point.interfaces.wifi.stop_ap()

        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()

        if self.send_data:
            wifisock_obj.wait_for_exit()

        time.sleep(10)


class Active_TX(ThreadBase):
    def __init__(self, power=None, wifi_dut=None, power_meter=None, rate=None, enable_11ax=0):
        self.power = power
        self.wifi_dut = wifi_dut
        self.power_meter = power_meter
        self.rate = rate
        self.enable_11ax = enable_11ax

    def run(self):
        length = 1000
        mode = 1
        channel = 1
        aggr_enable = 0

        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter)

        self.wifi_dut.interfaces.wifi.set_antenna(interface="client", antenna=4)
        logger().info(f"setting the wireless antenna ")

        logger().info(f"configuring dut with diff power:{self.power}")

        self.wifi_dut.interfaces.wifi.sl_si91x_transmit_test_start(
            enable=1,
            power=self.power,
            rate=self.rate,
            length=length,
            mode=mode,
            channel=channel,
            aggr_enable=aggr_enable,
            enable_11ax=self.enable_11ax,
        )
        logger().info(f"Transmit Test started.")
        time.sleep(5)

        pm_obj.start()
        pm_obj.wait_for_exit()

        self.wifi_dut.interfaces.wifi.sl_si91x_transmit_test_stop()

        time.sleep(15)


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
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.parametrize("dtim", [1])
@pytest.mark.test_src_map_id('C402869')
def test_wlan_standby_lis_int_1_with_mqtt_ka_5mins_C402869(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                          sl_collections, request, performance_data, mqtt_server,
                                                          custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    stdby_obj = StandBy_Associated(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, capture_time=320,
                                   sl_collections=sl_collections, power_meter=power_meter, mqtt_ka_enable=True,
                                   m4_sleep_time=300000, mqtt_server=mqtt_server)
    stdby_obj.start()
    stdby_obj.wait_for_exit()

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

# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.parametrize("dtim", [1])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C402870')
def test_wlan_standby_associated_listen_interval_C402870(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                               sl_collections, dtim, request, performance_data,
                                               custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[
        0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    stdby_obj = StandBy_Associated(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, capture_time=320,
                                   sl_collections=sl_collections, power_meter=power_meter, m4_sleep_time=300000)
    stdby_obj.start()
    stdby_obj.wait_for_exit()

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