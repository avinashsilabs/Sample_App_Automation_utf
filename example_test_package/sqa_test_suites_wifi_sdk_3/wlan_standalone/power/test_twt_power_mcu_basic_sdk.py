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
        logger().info(f"setting output channels")
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

        time.sleep(2)
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
        if not self.without_ip:
            self.device_ip = dictionary['device_ip']

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
        Power_Device.power_measurement(power_device=self.power_device, power_meter=self.power_meter, capture_time=self.capture_time)

class StandBy_Associated(ThreadBase):
    def __init__(self, dtim=None, wifi_dut=None, wifi_access_point=None, sl_collections=None, power_meter=None, deep_sleep=False, dtim_aligned_type=1,
                  remote_socket=None, send_data=False, capture_time=60, m4_sleep_time=100000, bcast_filter=True, tcp_ka_time=240, send_ka=False):
        self.dtim = dtim
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.wifi_access_point=wifi_access_point
        self.power_meter = power_meter
        self.deep_sleep = deep_sleep
        self.remote_socket = remote_socket
        self.send_data = send_data
        self.send_ka = send_ka
        self.capture_time = capture_time
        self.m4_sleep_time = m4_sleep_time
        self.bcast_filter = bcast_filter
        self.tcp_ka_time = tcp_ka_time
        self.dtim_aligned_type =dtim_aligned_type

    def run(self):
        logger().info(f"M4-TA secure handshake")
        self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)

        time.sleep(2)

        self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface = 'client',
            join_feature_bitmap = Si91xJoinFeatureBitMap.Default
        )
        wlan_obj = WlanThread(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, dtim=self.dtim,
                            sl_collections=self.sl_collections)
        if self.deep_sleep:
            m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time, deep_sleep_without_ret=True)
        else:
            m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time)
        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter, capture_time=self.capture_time)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        if self.send_data or self.send_ka:
                device2_ip = wlan_obj.getter()
                wifisock_obj = WifiSockthread(remote_socket=self.remote_socket, wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, device2_ip=device2_ip, 
                                              m4_deep_sleep=True, tcp_ka_time=self.tcp_ka_time, send_ka=self.send_ka, send_data=self.send_data)
                wifisock_obj.start()

        time.sleep(2)

        if self.bcast_filter:
            logger().info(f"Setting filter broadcast command")
            self.wifi_dut.interfaces.wifi.set_filter_broadcast()


        time.sleep(2)

        logger().info(f"Enabling TA power save")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save", dtim_aligned_type=self.dtim_aligned_type)
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

pytestmark = [pytest.mark.firmware_app("test_480K_M4SS_192K")]   

# ********************************************************************************************************************


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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"] )
def test_standby_power_twt_disable_without_ip_C129918(firmware_loader, power_meter,  wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request):
     test_name = request.node.name
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     logger().info(f"M4-TA secure handshake")
     wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, without_ip=True,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter)

     wlan_obj.start()
     wlan_obj.wait_for_exit()
 
     time.sleep(2)

     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(80)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()
 
     time.sleep(10)



# ********************************************************************************************************************


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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"] )
def test_standby_power_twt_disable_with_ip_C129919(firmware_loader, power_meter,  wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request):
     test_name = request.node.name
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     logger().info(f"M4-TA secure handshake")
     wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter)
 
     wlan_obj.start()
     wlan_obj.wait_for_exit()
 
     time.sleep(2)
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(80)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()
 
     time.sleep(10)


# ********************************************************************************************************************


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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"] )
def test_standby_power_twt_disable_tcp_ka_C129920(firmware_loader, power_meter,  wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request, remote_socket):
     test_name = request.node.name
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     logger().info(f"M4-TA secure handshake")
     wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter)
 
     wlan_obj.start()
     wlan_obj.wait_for_exit()

     device2_ip = wlan_obj.getter()

     wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, device2_ip=device2_ip, m4_deep_sleep=False, tcp_ka_time=240)

     wifi_sock_obj.start()
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(80)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()

     wifi_sock_obj.wait_for_exit()
 
     time.sleep(10)


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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"] )
def test_standby_power_twt_enable_without_ip_C129922(firmware_loader, power_meter,  wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request):
     test_name = request.node.name
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     logger().info(f"M4-TA secure handshake")
     wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, without_ip=True,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter)
 
     wlan_obj.start()
     wlan_obj.wait_for_exit()
 
     time.sleep(2)

     wifi_dut.interfaces.wifi.set_twt(
                wake_duration=0x60,
                wake_duration_tol=0x60,
                wake_int_exp=13,
                wake_int_exp_tol=13,
                wake_int_mantissa=0x1D4C,
                wake_int_mantissa_tol=0x1D4C,
                implicit_twt=1,
                un_announced_twt=1,
                triggered_twt=0,
                negotiation_type=0,
                twt_channel=0,
                twt_protection=0,
                twt_flow_id=1,
                restrict_tx_outside_tsp=1,
                twt_retry_limit=6,
                twt_retry_interval=10,
                req_type=1,
                twt_enable=1,
                wake_duration_unit=0
     )
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(80)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()
 
     time.sleep(10)


# ********************************************************************************************************************


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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"] )
def test_standby_power_twt_enable_with_ip_C129923(firmware_loader, power_meter,  wifi_dut, wifi_access_point, wifi_sniffer, sl_collections, request):
     test_name = request.node.name
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     logger().info(f"M4-TA secure handshake")
     wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, m4_sleep_time=220000)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter, capture_time=90)

     wlan_obj.start()
     wlan_obj.wait_for_exit()
 
     time.sleep(2)

     wifi_dut.interfaces.wifi.set_twt(
                wake_duration=0x60,
                wake_duration_tol=0x60,
                wake_int_exp=13,
                wake_int_exp_tol=13,
                wake_int_mantissa=0x1D4C,
                wake_int_mantissa_tol=0x1D4C,
                implicit_twt=1,
                un_announced_twt=1,
                triggered_twt=0,
                negotiation_type=0,
                twt_channel=0,
                twt_protection=0,
                twt_flow_id=1,
                restrict_tx_outside_tsp=1,
                twt_retry_limit=6,
                twt_retry_interval=10,
                req_type=1,
                twt_enable=1,
                wake_duration_unit=0
     )
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(80)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()
 
     time.sleep(10)


# ********************************************************************************************************************


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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"] )
def test_standby_power_twt_enable_tcp_ka_C129924(firmware_loader, power_meter,  wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request, remote_socket):
     test_name = request.node.name
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     logger().info(f"M4-TA secure handshake")
     wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter)
 
     wlan_obj.start()
     wlan_obj.wait_for_exit()

     device2_ip = wlan_obj.getter()

     wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, device2_ip=device2_ip, m4_deep_sleep=False, tcp_ka_time=240)

     wifi_sock_obj.start()

     wifi_dut.interfaces.wifi.set_twt(
                wake_duration=0x60,
                wake_duration_tol=0x60,
                wake_int_exp=13,
                wake_int_exp_tol=13,
                wake_int_mantissa=0x1D4C,
                wake_int_mantissa_tol=0x1D4C,
                implicit_twt=1,
                un_announced_twt=1,
                triggered_twt=0,
                negotiation_type=0,
                twt_channel=0,
                twt_protection=0,
                twt_flow_id=1,
                restrict_tx_outside_tsp=1,
                twt_retry_limit=6,
                twt_retry_interval=10,
                req_type=1,
                twt_enable=1,
                wake_duration_unit=0
     )
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(80)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()

     wifi_sock_obj.wait_for_exit()
 
     time.sleep(10)


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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"] )
def test_standby_power_announced_twt_enable_without_ip_C129927(firmware_loader, power_meter,  wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request):
     test_name = request.node.name
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     logger().info(f"M4-TA secure handshake")
     wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, without_ip=True,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter)
 
     wlan_obj.start()
     wlan_obj.wait_for_exit()
 
     time.sleep(2)

     wifi_dut.interfaces.wifi.set_twt(
                wake_duration=0x60,
                wake_duration_tol=0x60,
                wake_int_exp=13,
                wake_int_exp_tol=13,
                wake_int_mantissa=0x1D4C,
                wake_int_mantissa_tol=0x1D4C,
                implicit_twt=1,
                un_announced_twt=0,
                triggered_twt=0,
                negotiation_type=0,
                twt_channel=0,
                twt_protection=0,
                twt_flow_id=1,
                restrict_tx_outside_tsp=1,
                twt_retry_limit=6,
                twt_retry_interval=10,
                req_type=1,
                twt_enable=1,
                wake_duration_unit=0
     )
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(80)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()
 
     time.sleep(10)


# ********************************************************************************************************************


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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"] )
def test_standby_power_announced_twt_enable_with_ip_C129928(firmware_loader, power_meter,  wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request):
     test_name = request.node.name
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     logger().info(f"M4-TA secure handshake")
     wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter)
 
     wlan_obj.start()
     wlan_obj.wait_for_exit()
 
     time.sleep(2)

     wifi_dut.interfaces.wifi.set_twt(
                wake_duration=0x60,
                wake_duration_tol=0x60,
                wake_int_exp=13,
                wake_int_exp_tol=13,
                wake_int_mantissa=0x1D4C,
                wake_int_mantissa_tol=0x1D4C,
                implicit_twt=1,
                un_announced_twt=0,
                triggered_twt=0,
                negotiation_type=0,
                twt_channel=0,
                twt_protection=0,
                twt_flow_id=1,
                restrict_tx_outside_tsp=1,
                twt_retry_limit=6,
                twt_retry_interval=10,
                req_type=1,
                twt_enable=1,
                wake_duration_unit=0
     )
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(80)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()
 
     time.sleep(10)


# ********************************************************************************************************************


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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"] )
def test_standby_power_announced_twt_enable_tcp_ka_C129929(firmware_loader, power_meter,  wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request, remote_socket):
     test_name = request.node.name
     wifi_sniffer.interfaces.capture.configure_interface(channel=1)
     wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
     logger().info(f"M4-TA secure handshake")
     wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)

     time.sleep(2)

     wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                         sl_collections=sl_collections)
     m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
     pm_obj = Power_Measurement_Thread(power_meter=power_meter)
 
     wlan_obj.start()
     wlan_obj.wait_for_exit()

     device2_ip = wlan_obj.getter()

     wifi_sock_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, device2_ip=device2_ip, m4_deep_sleep=False, tcp_ka_time=240)

     wifi_sock_obj.start()

     wifi_dut.interfaces.wifi.set_twt(
                wake_duration=0x60,
                wake_duration_tol=0x60,
                wake_int_exp=13,
                wake_int_exp_tol=13,
                wake_int_mantissa=0x1D4C,
                wake_int_mantissa_tol=0x1D4C,
                implicit_twt=1,
                un_announced_twt=0,
                triggered_twt=0,
                negotiation_type=0,
                twt_channel=0,
                twt_protection=0,
                twt_flow_id=1,
                restrict_tx_outside_tsp=1,
                twt_retry_limit=6,
                twt_retry_interval=10,
                req_type=1,
                twt_enable=1,
                wake_duration_unit=0
     )
 
     logger().info(f"Setting filter broadcast command")
     wifi_dut.interfaces.wifi.set_filter_broadcast()

     logger().info(f"Enabling TA power save")
     wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
     time.sleep(2)

     m4_obj.start()
     time.sleep(80)
     pm_obj.start()
     pm_obj.wait_for_exit()
     m4_obj.wait_for_exit()

     wifi_sock_obj.wait_for_exit()
 
     time.sleep(10)


# ********************************************************************************************************************


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.parametrize("keep_alive_time", [60])
def test_standby_power_twt_disable_mqtt_ka_C129921(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                   sl_collections, mqtt_server, keep_alive_time, wifi_sniffer, request):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

    time.sleep(2)

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()

    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client_power",
                                                                    keep_alive_interval=keep_alive_time)
    logger().info("DUT connecting to MQTT server")
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)

    time.sleep(5)

    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()

    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)

    m4_obj.start()
    time.sleep(80)
    pm_obj.start()
    pm_obj.wait_for_exit()
    m4_obj.wait_for_exit()

    time.sleep(10)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.parametrize("keep_alive_time", [60])
def test_standby_power_twt_enable_mqtt_ka_C129925(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                  sl_collections, mqtt_server, keep_alive_time, wifi_sniffer, request):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

    time.sleep(2)

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()

    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client_power",
                                                                    keep_alive_interval=keep_alive_time)
    logger().info("DUT connecting to MQTT server")
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)

    time.sleep(5)

    wifi_dut.interfaces.wifi.set_twt(
        wake_duration=0x60,
        wake_duration_tol=0x60,
        wake_int_exp=13,
        wake_int_exp_tol=13,
        wake_int_mantissa=0x1D4C,
        wake_int_mantissa_tol=0x1D4C,
        implicit_twt=1,
        un_announced_twt=1,
        triggered_twt=0,
        negotiation_type=0,
        twt_channel=0,
        twt_protection=0,
        twt_flow_id=1,
        restrict_tx_outside_tsp=1,
        twt_retry_limit=6,
        twt_retry_interval=10,
        req_type=1,
        twt_enable=1,
        wake_duration_unit=0
    )

    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()

    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)

    m4_obj.start()
    time.sleep(80)
    pm_obj.start()
    pm_obj.wait_for_exit()
    m4_obj.wait_for_exit()

    time.sleep(10)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.DisableDebugPrints,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.parametrize("keep_alive_time", [60])
def test_standby_power_announced_twt_enable_mqtt_ka_C129926(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                            sl_collections, mqtt_server, keep_alive_time, wifi_sniffer,
                                                            request):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

    time.sleep(2)

    wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          sl_collections=sl_collections)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    wlan_obj.start()
    wlan_obj.wait_for_exit()

    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client_power",
                                                                    keep_alive_interval=keep_alive_time)
    logger().info("DUT connecting to MQTT server")
    wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)

    time.sleep(5)

    wifi_dut.interfaces.wifi.set_twt(
        wake_duration=0x60,
        wake_duration_tol=0x60,
        wake_int_exp=13,
        wake_int_exp_tol=13,
        wake_int_mantissa=0x1D4C,
        wake_int_mantissa_tol=0x1D4C,
        implicit_twt=1,
        un_announced_twt=0,
        triggered_twt=0,
        negotiation_type=0,
        twt_channel=0,
        twt_protection=0,
        twt_flow_id=1,
        restrict_tx_outside_tsp=1,
        twt_retry_limit=6,
        twt_retry_interval=10,
        req_type=1,
        twt_enable=0,
        wake_duration_unit=0
    )

    logger().info(f"Setting filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast()

    logger().info(f"Enabling TA power save")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
    time.sleep(2)

    m4_obj.start()
    time.sleep(80)
    pm_obj.start()
    pm_obj.wait_for_exit()
    m4_obj.wait_for_exit()

    wifi_dut.interfaces.wifi.get_mac_address()

    time.sleep(10)

# ********************************************************************************************************************

