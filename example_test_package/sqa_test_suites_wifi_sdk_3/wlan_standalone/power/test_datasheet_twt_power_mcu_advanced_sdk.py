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
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log_{self.dtim}", data_log_stop_after_elapsed_time=self.capture_time)
        else:
            logger().info(f"initiating power meter")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log", data_log_stop_after_elapsed_time=self.capture_time)
        # Init power meter module

        self.power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
        # set power meter out put channels
        if dut == "si917_ncp_sl_wifi":
            self.power_meter.interfaces.power_meter.set_output_channels_settings(
            [{"channel": "1", "emulation_mode": "Current Measure", "trace_current": True, "trace_voltage": False,
              "trace_power": False}])
            
        else:
            self.power_meter.interfaces.power_meter.set_output_channels_settings([{"channel": "3",
                                                                        "emulation_mode": "2 Quadrant Power Supply",
                                                                        "voltage": "3.3000", "current_limit": "1.00000",
                                                                        "voltage_slew": "MAX",
                                                                        "voltage_meter_range": "Auto",
                                                                        "current_meter_range": "Auto",
                                                                        "trace_current": True, "trace_power": True}])
        
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

    def __init__(self, remote_socket=None, wifi_dut=None, wifi_access_point=None, device2_ip=None, m4_deep_sleep=False, tcp_ka_time=240, send_data=False, send_ka=False):
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
        device2_ip=self.device2_ip
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
        time.sleep(5)
        if self.send_ka:
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd = sock_id,
            option_level = 'SOL_SOCKET',
            option_name = 'SO_KEEPALIVE',
            option_val = str(self.tcp_ka_time))

        elif self.send_data:
            for i in range(1, no_of_iterations):
                self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock_id,
                                                            data=data)
                data = self.remote_socket.interfaces.socket.recv_data_tcp(data_size)
                time.sleep(self.tcp_ka_time)

        time.sleep(5)
        if not self.m4_deep_sleep:
            result = self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            assert b"success" in result, "unable to close opened tcp socket"
        self.remote_socket.interfaces.socket.socket_close_indication(1)


class WlanThread(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None,
                 dtim=10, listen_interval=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.dtim = dtim
        self.listen_interval = listen_interval
        self.device_ip = None

    def run(self):
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
                                                                      sleep_time=self.m4_sleep_time,
                                                                      timeout = 600
                                                                      )
        else:
            self.wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=self.m4_sleep_time,
                                                           timeout = 600)
            
class Power_Measurement_Thread(ThreadBase, Power_Device):


    def __init__(self, power_meter=None, capture_time=60):
        super().__init__()
        Power_Device().__init__()
        self.power_meter = power_meter
        self.capture_time = capture_time
	
    def run(self):
        logger().info(f"Starting Power Capture")
        self.power_device = UtfConfig.instance().defaults.get("power_meter", {})
        Power_Device.power_measurement(power_device=self.power_device, power_meter=self.power_meter, capture_time=self.capture_time)


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
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "enable_timeout_config": 1,
        "keep_alive_timeout_value": 30,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C129923')
def test_twt_power_2s_twt_int_wlan_ka_30s_C129923(firmware_loader, power_meter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request, performance_data, custom_performance_fixture):
     performance_file_root_dir, perf_file_name = custom_performance_fixture
     obtained_test_name = request.node.name
     test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

     opn = UtfConfig.instance().defaults.get("opn", {})
     build_number = UtfConfig.instance().defaults.get("build_number", {})
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     dut = UtfConfig.instance().defaults.get("dut", {})
     logger().info(f"dut: {dut}")

     if dut != "si917_ncp_sl_wifi":
         logger().info(f"M4-TA secure handshake")
         wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                         sl_collections=sl_collections)
     if dut != "si917_ncp_sl_wifi":
         m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, deep_sleep_without_ret=True, m4_sleep_time=180000)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter)
 
     wlan_obj.start()
     wlan_obj.wait_for_exit()
 
     time.sleep(2)

     wifi_dut.interfaces.wifi.twt_auto_config(
                twt_enable=1,
                average_tx_throughput="\"0\"",
                tx_latency="\"0\"",
                rx_latency=2000,
                device_average_throughput=20000,
                estimated_extra_wake_duration_percent="\"0\"",
                twt_tolerable_deviation=10,
                default_wake_interval_ms=1024,
                default_minimum_wake_duration_ms=8,
                beacon_wake_up_count_after_sp=2
                )                                                                                                                                                                                                                                                                                                                            
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")

     time.sleep(60)

     if dut != "si917_ncp_sl_wifi":
         m4_obj.start()
     time.sleep(10)
     pm_obj.start()
     pm_obj.wait_for_exit()
     if dut != "si917_ncp_sl_wifi":
         m4_obj.wait_for_exit()
 
     parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
     __print_throughput(parsed_result)
     assert parsed_result["Output"] is not None
     performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_352K_M4SS_320K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )

     time.sleep(10)


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
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": 1,
        "keep_alive_timeout_value": 30,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C129923')
def test_twt_power_30s_twt_int_wlan_ka_30s_C129923(firmware_loader, power_meter, wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, request, performance_data, custom_performance_fixture):
     performance_file_root_dir, perf_file_name = custom_performance_fixture
     obtained_test_name = request.node.name
     test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

     opn = UtfConfig.instance().defaults.get("opn", {})
     build_number = UtfConfig.instance().defaults.get("build_number", {})
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     dut = UtfConfig.instance().defaults.get("dut", {})
     logger().info(f"dut: {dut}")

     if dut != "si917_ncp_sl_wifi":
         logger().info(f"M4-TA secure handshake")
         wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, deep_sleep_without_ret=True, m4_sleep_time=180000)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter)
 
     wlan_obj.start()
     wlan_obj.wait_for_exit()
 
     time.sleep(10)

     wifi_dut.interfaces.wifi.twt_auto_config(
                twt_enable=1,
                average_tx_throughput="\"0\"",
                tx_latency="\"0\"",
                rx_latency=30000,
                device_average_throughput=20000,
                estimated_extra_wake_duration_percent="\"0\"",
                twt_tolerable_deviation=10,
                default_wake_interval_ms=1024,
                default_minimum_wake_duration_ms=8,
                beacon_wake_up_count_after_sp=2
                )   
                                                                                                                                                                                                                                                                                                                              
     time.sleep(5)
     
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")

     time.sleep(60)

     m4_obj.start()
     time.sleep(10)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()
 
     parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
     __print_throughput(parsed_result)
     assert parsed_result["Output"] is not None
     performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_352K_M4SS_320K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )

     time.sleep(10)


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
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "enable_timeout_config": 1,
        "keep_alive_timeout_value": 60,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C129923')
def test_twt_power_60s_twt_int_wlan_ka_60s_C129923(firmware_loader, power_meter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request, performance_data, custom_performance_fixture):
     performance_file_root_dir, perf_file_name = custom_performance_fixture
     obtained_test_name = request.node.name
     test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

     opn = UtfConfig.instance().defaults.get("opn", {})
     build_number = UtfConfig.instance().defaults.get("build_number", {})
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     dut = UtfConfig.instance().defaults.get("dut", {})
     logger().info(f"dut: {dut}")

     if dut != "si917_ncp_sl_wifi":
         logger().info(f"M4-TA secure handshake")
         wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, deep_sleep_without_ret=True, m4_sleep_time=180000)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter)
 
     wlan_obj.start()
     wlan_obj.wait_for_exit()
 
     time.sleep(2)

     wifi_dut.interfaces.wifi.twt_auto_config(
                twt_enable=1,
                average_tx_throughput="\"0\"",
                tx_latency="\"0\"",
                rx_latency=60000,
                device_average_throughput=20000,
                estimated_extra_wake_duration_percent="\"0\"",
                twt_tolerable_deviation=10,
                default_wake_interval_ms=1024,
                default_minimum_wake_duration_ms=8,
                beacon_wake_up_count_after_sp=2
                )                                                                                                                                                                                                                                                                                                                            
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(60)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()
 
     parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
     __print_throughput(parsed_result)
     assert parsed_result["Output"] is not None
     performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_352K_M4SS_320K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )

     time.sleep(10)


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
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "enable_timeout_config": 1,
        "keep_alive_timeout_value": 30,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C129923')
def test_twt_power_2s_twt_int_wlan_ka_30s_tcp_ka_240s_C129923(firmware_loader, power_meter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request, remote_socket, performance_data, custom_performance_fixture):
     performance_file_root_dir, perf_file_name = custom_performance_fixture
     obtained_test_name = request.node.name
     test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

     opn = UtfConfig.instance().defaults.get("opn", {})
     build_number = UtfConfig.instance().defaults.get("build_number", {})
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     dut = UtfConfig.instance().defaults.get("dut", {})
     logger().info(f"dut: {dut}")

     if dut != "si917_ncp_sl_wifi":
         logger().info(f"M4-TA secure handshake")
         wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, deep_sleep_without_ret=True, m4_sleep_time=480000)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter, capture_time=240)

     wlan_obj.start()
     wlan_obj.wait_for_exit()

     device2_ip = wlan_obj.getter()

     wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, 
                                    device2_ip=device2_ip, m4_deep_sleep=True, send_ka=True, tcp_ka_time=240)

     wifi_sock_obj.start()
 
     time.sleep(2)

     wifi_dut.interfaces.wifi.twt_auto_config(
                twt_enable=1,
                average_tx_throughput="\"0\"",
                tx_latency="\"0\"",
                rx_latency=2000,
                device_average_throughput=20000,
                estimated_extra_wake_duration_percent="\"0\"",
                twt_tolerable_deviation=10,
                default_wake_interval_ms=1024,
                default_minimum_wake_duration_ms=8,
                beacon_wake_up_count_after_sp=2
                )                                                                                                                                                                                                                                                                                                                            
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(50)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()

     wifi_sock_obj.wait_for_exit()
 
     parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
     __print_throughput(parsed_result)
     assert parsed_result["Output"] is not None
     performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_352K_M4SS_320K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )

     time.sleep(10)


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
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "enable_timeout_config": 1,
        "keep_alive_timeout_value": 30,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C129923')
def test_twt_power_30s_twt_int_wlan_ka_30s_tcp_ka_240s_C129923(firmware_loader, power_meter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request, remote_socket, performance_data, custom_performance_fixture):
     performance_file_root_dir, perf_file_name = custom_performance_fixture
     obtained_test_name = request.node.name
     test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

     opn = UtfConfig.instance().defaults.get("opn", {})
     build_number = UtfConfig.instance().defaults.get("build_number", {})
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     dut = UtfConfig.instance().defaults.get("dut", {})
     logger().info(f"dut: {dut}")

     if dut != "si917_ncp_sl_wifi":
         logger().info(f"M4-TA secure handshake")
         wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, deep_sleep_without_ret=True, m4_sleep_time=480000)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter, capture_time=240)
 
     wlan_obj.start()
     wlan_obj.wait_for_exit()

     device2_ip = wlan_obj.getter()

     wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, 
                                    device2_ip=device2_ip, m4_deep_sleep=True, send_ka=True, tcp_ka_time=240)
     wifi_sock_obj.start()
 
     time.sleep(2)

     wifi_dut.interfaces.wifi.twt_auto_config(
                twt_enable=1,
                average_tx_throughput="\"0\"",
                tx_latency="\"0\"",
                rx_latency=30000,
                device_average_throughput=20000,
                estimated_extra_wake_duration_percent="\"0\"",
                twt_tolerable_deviation=10,
                default_wake_interval_ms=1024,
                default_minimum_wake_duration_ms=8,
                beacon_wake_up_count_after_sp=2
                )                                                                                                                                                                                                                                                                                                                            
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(50)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()

     wifi_sock_obj.wait_for_exit()
 
     parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
     __print_throughput(parsed_result)
     assert parsed_result["Output"] is not None
     performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_352K_M4SS_320K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )

     time.sleep(10)


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
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "enable_timeout_config": 1,
        "keep_alive_timeout_value": 60,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C129923')
def test_twt_power_60s_twt_int_wlan_ka_60s_tcp_ka_240s_C129923(firmware_loader, power_meter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request, remote_socket, performance_data, custom_performance_fixture):
     performance_file_root_dir, perf_file_name = custom_performance_fixture
     obtained_test_name = request.node.name
     test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

     opn = UtfConfig.instance().defaults.get("opn", {})
     build_number = UtfConfig.instance().defaults.get("build_number", {})
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     dut = UtfConfig.instance().defaults.get("dut", {})
     logger().info(f"dut: {dut}")

     if dut != "si917_ncp_sl_wifi":
         logger().info(f"M4-TA secure handshake")
         wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, deep_sleep_without_ret=True, m4_sleep_time=480000)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter, capture_time=300)
 
     wlan_obj.start()
     wlan_obj.wait_for_exit()

     device2_ip = wlan_obj.getter()

     wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, 
                                    device2_ip=device2_ip, m4_deep_sleep=True, send_ka=True, tcp_ka_time=240)
     wifi_sock_obj.start()
 
     time.sleep(2)

     wifi_dut.interfaces.wifi.twt_auto_config(
                twt_enable=1,
                average_tx_throughput="\"0\"",
                tx_latency="\"0\"",
                rx_latency=60000,
                device_average_throughput=20000,
                estimated_extra_wake_duration_percent="\"0\"",
                twt_tolerable_deviation=10,
                default_wake_interval_ms=1024,
                default_minimum_wake_duration_ms=8,
                beacon_wake_up_count_after_sp=2
                )                                                                                                                                                                                                                                                                                                                            
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(50)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()

     wifi_sock_obj.wait_for_exit()
 
     parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
     __print_throughput(parsed_result)
     assert parsed_result["Output"] is not None
     performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                          opn=opn, 
                                                          build_number=build_number,
                                                          memory_configuration="test_352K_M4SS_320K",
                                                          parsed_result=parsed_result["Output"],
                                                          file_path = performance_file_root_dir,
                                                          file_name = perf_file_name
                                                          )

     time.sleep(10)


# ********************************************************************************************************************