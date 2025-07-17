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
        logger().info(f"setting output channels")

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
                                                                      sleep_time=self.m4_sleep_time,
                                                                      timeout=400
                                                                      )
        else:
            self.wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=self.m4_sleep_time, timeout=150)
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
        Power_Device.power_measurement(power_device=self.power_device, power_meter=self.power_meter, capture_time=self.capture_time)

class StandBy_Associated(ThreadBase):
    def __init__(self, dtim=None, wifi_dut=None, wifi_access_point=None, sl_collections=None, power_meter=None, deep_sleep=False, dtim_aligned_type=1,
                  remote_socket=None, send_data=False, capture_time=60, m4_sleep_time=120000, bcast_filter=True, tcp_ka_time=240, send_ka=False, listen_case=False):
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
        self.listen_case = listen_case

    def run(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        
        # logger().info(f"M4-TA secure handshake")
        # self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)

        time.sleep(2)

        self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface = 'client',
            join_feature_bitmap = Si91xJoinFeatureBitMap.Default
        )
        wlan_obj = WlanThread(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, dtim=self.dtim,
                            sl_collections=self.sl_collections)
        if dut != "si917_ncp_sl_wifi":
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
        length=100
        mode=1
        channel=1
        aggr_enable=0

        # pm_obj = Power_Measurement_Thread(power_meter=self.power_meter)

        self.wifi_dut.interfaces.wifi.set_antenna(interface="client", antenna=4)
        logger().info(f"setting the wireless antenna ")

        logger().info(f"configuring dut with diff power:{self.power}")

        self.wifi_dut.interfaces.wifi.sl_si91x_transmit_test_start(
                enable= 1,
                power= self.power,
                rate=self.rate,
                length=length,
                mode=mode,
                channel=channel,
                aggr_enable=aggr_enable,
                enable_11ax=self.enable_11ax,
                )
        logger().info(f"Transmit Test started.")
        
        time.sleep(100)
   

# ********************************************************************************************************************

pytestmark = [pytest.mark.firmware_app("test_416K_M4SS_256K")]   

# ********************************************************************************************************************


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 0, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wlan_standby_associated_DTIM_10_C20637(firmware_loader, power_meter, wifi_access_point, wifi_dut, sl_collections, dtim, wifi_sniffer, request):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    stdby_obj=StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections, power_meter=power_meter, deep_sleep=True)
    stdby_obj.start()
    stdby_obj.wait_for_exit()


# ********************************************************************************************************************




@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 0, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wlan_standby_associated_DTIM_10_TCP_KA_240s_C20637(firmware_loader, power_meter, wifi_access_point, wifi_sniffer, request, wifi_dut, sl_collections, dtim, remote_socket):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    stdby_obj=StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,power_meter=power_meter, 
                                 deep_sleep=True, remote_socket=remote_socket, send_ka=True, capture_time=300, m4_sleep_time=350000, tcp_ka_time=240)
    stdby_obj.start()
    stdby_obj.wait_for_exit()


# ********************************************************************************************************************


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled ,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
def test_wlan_power_save_without_ram_ret_C20640(firmware_loader, power_meter, wifi_dut):
    
    dut = UtfConfig.instance().defaults.get("dut", {})
    logger().info(f"dut: {dut}")

    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)
    time.sleep(2)

    if dut != "si917_ncp_sl_wifi":
        m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, deep_sleep_without_ret=True)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    logger().info(f"Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save")
    time.sleep(2)

    if dut != "si917_ncp_sl_wifi":
            m4_obj.start()
            time.sleep(2)
            
    pm_obj.start()
    pm_obj.wait_for_exit()

    if dut != "si917_ncp_sl_wifi":
        m4_obj.wait_for_exit()

    time.sleep(15)


# ********************************************************************************************************************


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 0, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_1mbps_listen_rx_C20641_C20642(firmware_loader, power_meter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request, dtim):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    stdby_obj=StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections, power_meter=power_meter, listen_case=True)
    stdby_obj.start()
    stdby_obj.wait_for_exit()


# ********************************************************************************************************************


@pytest.mark.parametrize("power", [127])
@pytest.mark.parametrize("rate", [1])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.PERMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | 
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)                           
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
def test_wlan_active_1mbps_tx_C652608(firmware_loader, power_meter, wifi_dut, power, rate, wifi_sniffer, request):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    active_obj = Active_TX(power=power, rate=rate, wifi_dut=wifi_dut, power_meter=power_meter, enable_11ax=1)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    active_obj.start()
    pm_obj.start()

    pm_obj.wait_for_exit()
    active_obj.wait_for_exit()

    wifi_dut.interfaces.wifi.sl_si91x_transmit_test_stop()


# ********************************************************************************************************************


@pytest.mark.parametrize("power", [127])
@pytest.mark.parametrize("rate", [256])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.PERMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | 
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
def test_wlan_active_tx_ht_mcs0_C652609(firmware_loader, power_meter, wifi_dut, power, rate, wifi_sniffer, request):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    active_obj = Active_TX(power=power, rate=rate, wifi_dut=wifi_dut, power_meter=power_meter, enable_11ax=1)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    active_obj.start()
    pm_obj.start()

    pm_obj.wait_for_exit()
    active_obj.wait_for_exit()

    wifi_dut.interfaces.wifi.sl_si91x_transmit_test_stop()


# ********************************************************************************************************************


@pytest.mark.parametrize("power", [127])
@pytest.mark.parametrize("rate", [263])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.PERMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | 
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
def test_wlan_active_tx_ht_mcs7_C652610(firmware_loader, power_meter, wifi_dut, power, rate, wifi_sniffer, request):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    active_obj = Active_TX(power=power, rate=rate, wifi_dut=wifi_dut, power_meter=power_meter, enable_11ax=1)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    active_obj.start()
    pm_obj.start()

    pm_obj.wait_for_exit()
    active_obj.wait_for_exit()

    wifi_dut.interfaces.wifi.sl_si91x_transmit_test_stop()


# ********************************************************************************************************************


@pytest.mark.parametrize("power", [127])
@pytest.mark.parametrize("rate", [256])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.PERMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | 
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
def test_wlan_active_tx_he_mcs0_C652611(firmware_loader, power_meter, wifi_dut, power, rate, wifi_sniffer, request):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    active_obj = Active_TX(power=power, rate=rate, wifi_dut=wifi_dut, power_meter=power_meter, enable_11ax=1)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    active_obj.start()
    pm_obj.start()

    pm_obj.wait_for_exit()
    active_obj.wait_for_exit()

    wifi_dut.interfaces.wifi.sl_si91x_transmit_test_stop()


# ********************************************************************************************************************


@pytest.mark.parametrize("power", [127])
@pytest.mark.parametrize("rate", [263])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.PERMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | 
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
def test_wlan_active_tx_he_mcs7_C652612(firmware_loader, power_meter, wifi_dut, power, rate, wifi_sniffer, request):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=1)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
    active_obj = Active_TX(power=power, rate=rate, wifi_dut=wifi_dut, power_meter=power_meter, enable_11ax=1)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    active_obj.start()
    pm_obj.start()

    pm_obj.wait_for_exit()
    active_obj.wait_for_exit()

    wifi_dut.interfaces.wifi.sl_si91x_transmit_test_stop()


# ********************************************************************************************************************

@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
def test_ble_sdk_per_1mbps_tx_LP_CHAIN_0dBm_C20663(firmware_loader, power_meter, bt_dut, sl_collections):
    "Verify BLE Active_2.4G 1Mbps Tx-0dBm_LP Chain"
    cmd_ix = 0x13
    access_addr = 1903575337
    pkt_len = 240
    phy_rate = 1
    rx_chnl_num = 10
    tx_chnl_num = 10
    scrambler_seed = 0
    le_chnl_type = 1
    payload_type = 0x06
    tx_power = 31
    transmit_mode = 1
    freq_hop_en = 0
    ant_sel = 2
    rf_type = 1
    pll_mode = 0
    inter_pkt_gap = 0
    num_pkts = 1000
    rf_chain = 3
    cmd_type = 8
    try:
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        logger().info("get dut bt address.....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
        logger().info(f'bt dut address {bt_dut_address}')
        logger().info("configure bt local name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='SILABS_BT')
        logger().info("get bt local name....")
        bt_dut.interfaces.bluetooth.bt_get_local_name()
        bt_dut.interfaces.bluetooth.set_ble_per_tx_params(cmd_ix=cmd_ix, transmit_enable=1, access_addr=access_addr,
                                                          phy_rate=phy_rate, rx_chnl_num=rx_chnl_num,
                                                          tx_chnl_num=tx_chnl_num,
                                                          scrambler_seed=scrambler_seed, le_chnl_type=le_chnl_type,
                                                          freq_hop_en=freq_hop_en, ant_sel=ant_sel, pll_mode=pll_mode,
                                                          rf_type=rf_type, rf_chain=rf_chain, pkt_len=pkt_len,
                                                          payload_type=payload_type, tx_power=tx_power,
                                                          transmit_mode=transmit_mode, inter_pkt_gap=inter_pkt_gap,
                                                          num_pkts=num_pkts)
        time.sleep(10)
        logger().info("starting per stats")
        bt_dut.interfaces.bluetooth.get_bt_per_tx_stats(cmd_type=cmd_type)
        time.sleep(5)
        pm_obj = Power_Measurement_Thread(power_meter=power_meter)
        if dut != "si917_ncp_sl_wifi":
            m4_obj = M4_Sleep_Thread(wifi_dut=bt_dut)

        if dut != "si917_ncp_sl_wifi":
            m4_obj.start()
            time.sleep(2)
            
        pm_obj.start()
        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()
        time.sleep(10)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=bt_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
def test_ble_sdk_per_1mbps_rx_LP_CHAIN_C20665(firmware_loader, power_meter, bt_dut, sl_collections):
    cmd_ix = 0x14
    access_addr = 1903575337
    ext_data_len_indication = 1
    loop_back_mode = 0
    duty_cycling_en = 0
    phy_rate = 1
    ant_sel = 2
    rf_type = 1
    pll_mode = 0
    rf_chain = 3
    cmd_type = 8
    config = "\"10 10 0 1 0\""
    try:
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        logger().info("get dut bt address.....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
        logger().info(f'bt dut address {bt_dut_address}')
        logger().info("configure bt local name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='SILABS_BT')
        logger().info("get bt local name....")
        bt_dut.interfaces.bluetooth.bt_get_local_name()
        bt_dut.interfaces.bluetooth.ble_per_receive(cmd_ix=cmd_ix,
                                                    receive_enable=1,
                                                    access_addr=access_addr,
                                                    phy_rate=phy_rate,
                                                    config = config,
                                                    ant_sel=ant_sel,
                                                    pll_mode=pll_mode,
                                                    rf_type=rf_type,
                                                    rf_chain=rf_chain,
                                                    ext_data_len_indication=ext_data_len_indication,
                                                    loop_back_mode=loop_back_mode,
                                                    duty_cycling_en=duty_cycling_en,
                                                    )
        time.sleep(10)
        logger().info("starting per stats")
        bt_dut.interfaces.bluetooth.get_bt_per_tx_stats(cmd_type=cmd_type)
        time.sleep(5)
        pm_obj = Power_Measurement_Thread(power_meter=power_meter)
        if dut != "si917_ncp_sl_wifi":
            m4_obj = M4_Sleep_Thread(wifi_dut=bt_dut)

        if dut != "si917_ncp_sl_wifi":
            m4_obj.start()
            time.sleep(2)
            
        pm_obj.start()
        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()
            time.sleep(10)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=bt_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
def test_ble_sdk_per_1mbps_tx_7p5_dBm_C20664(firmware_loader, power_meter, bt_dut, sl_collections):
    """Verify BLE Active_2.4G 1Mbps Tx-10dBm_LP Chain"""
    cmd_ix = 0x13
    access_addr = 1903575337
    pkt_len = 240
    phy_rate = 1
    rx_chnl_num = 10
    tx_chnl_num = 10
    scrambler_seed = 0
    le_chnl_type = 1
    payload_type = 0x06
    tx_power = 63
    transmit_mode = 1
    freq_hop_en = 0
    ant_sel = 2
    rf_type = 1
    pll_mode = 0
    inter_pkt_gap = 0
    num_pkts = 1000
    rf_chain = 3
    cmd_type = 8
    try:
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        logger().info("get dut bt address.....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
        logger().info(f'bt dut address {bt_dut_address}')
        logger().info("configure bt local name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='SILABS_BLE')
        logger().info("get bt local name....")
        bt_dut.interfaces.bluetooth.bt_get_local_name()
        bt_dut.interfaces.bluetooth.set_ble_per_tx_params(cmd_ix=cmd_ix, transmit_enable=1, access_addr=access_addr,
                                                          phy_rate=phy_rate, rx_chnl_num=rx_chnl_num,
                                                          tx_chnl_num=tx_chnl_num,
                                                          scrambler_seed=scrambler_seed, le_chnl_type=le_chnl_type,
                                                          freq_hop_en=freq_hop_en, ant_sel=ant_sel, pll_mode=pll_mode,
                                                          rf_type=rf_type, rf_chain=rf_chain, pkt_len=pkt_len,
                                                          payload_type=payload_type, tx_power=tx_power,
                                                          transmit_mode=transmit_mode, inter_pkt_gap=inter_pkt_gap,
                                                          num_pkts=num_pkts)
        time.sleep(10)
        logger().info("starting per stats")
        bt_dut.interfaces.bluetooth.get_bt_per_tx_stats(cmd_type=cmd_type)
        time.sleep(5)
        pm_obj = Power_Measurement_Thread(power_meter=power_meter)
        if dut != "si917_ncp_sl_wifi":
            m4_obj = M4_Sleep_Thread(wifi_dut=bt_dut)
        
        if dut != "si917_ncp_sl_wifi":
            m4_obj.start()
            time.sleep(2)
            
        pm_obj.start()
        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()
            time.sleep(10)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=bt_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
def test_ble_sdk_advertise_non_connectable_power_0dBm_C20657(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections):
    """ Verify BLE Undirected Non-Connectable Advertisement"""
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_advertise_non_connectable_power{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            logger().info(f"M4-TA secure handshake")
            wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            logger().info("keeping the DUT in undirected_non_connectable_adv mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=131, ble_adv_int_min=2048, ble_adv_int_max=2048,
                                                           ble_adv_channel_map=7)
            logger().info("Initiating power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")

            logger().info("Initiating scanning from Remote remote device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch bluetooth address from remote device"
            scan_result = device_scan_result()
            device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                            bt_dut_address=bt_dut_address,
                                                                            adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            if device_found:
                logger().info("Dut found in scan results")
            logger().info("initiating stop scanning")
            ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "dut not found in scan results"
            logger().info(f"Getting Remote BLE characteristics by passing address "
                          f"{wifi_dut.interfaces.wifi.ble_address} from BTmon logs")

            bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

            logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")

            assert (
                    "Non connectable undirected - ADV_NONCONN_IND (0x03)"
                    in bt_logs.device_adv_type
            ), "Expected avd type not found bt mon logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
            time.sleep(5)
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, deep_sleep_without_ret=True)
            if dut != "si917_ncp_sl_wifi":
                m4_obj.start()
                time.sleep(2)
            
            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            time.sleep(10)

        except Exception as error:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "enable_ble_power_index_params": 1,
            "power_index": 31,
        },
    )
def test_ble_sdk_advertise_connectable_power_0_dBm_C20658(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections):
    """ Verify BLE Undirected Connectable advertisement """
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_advertise_connectable_power_{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            logger().info(f"M4-TA secure handshake")
            wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            logger().info("keeping the DUT in undirected_connectable ADV mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2048, ble_adv_int_max=2048,
                                                           ble_adv_channel_map=7)
            logger().info("Enabling power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")

            logger().info("Initiating scan from remote BLE device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch remote bluetooth address"
            scan_result = device_scan_result()
            device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                            bt_dut_address=bt_dut_address,
                                                                            adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            logger().info("Initiating stop scanning from remote device")
            ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "Dut not found in scan results"
            logger().info(f"Getting Remote BLE characteristics by passing address "
                          f"{wifi_dut.interfaces.wifi.ble_address} from BTmon logs")

            bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

            logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")

            assert "Connectable undirected - ADV_IND (0x00)" in bt_logs.device_adv_type, \
                "Expected adv type not found in bt mon logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
            time.sleep(5)
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, deep_sleep_without_ret=True)
            if dut != "si917_ncp_sl_wifi":
                    m4_obj.start()
                    time.sleep(2)
                    
            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            time.sleep(10)

        except Exception as error:
           sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************

# @pytest.mark.skip()
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | 
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_connect_with_1_28ms_0dBm_20660(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections):
    """Verify ble connection with 1.28ms """
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_connection_C20660_power{int(time.time())}.log",
    ) as bt_logs:
        try:
            logger().info(f"M4-TA secure handshake")
            wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2048, ble_adv_int_max=2048,
                                                           ble_adv_channel_map=7)
            logger().info("Initiating power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")

            logger().info("Initiating scan from remote device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"
            scan_result = device_scan_result()
            device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                            bt_dut_address=bt_dut_address,
                                                                            adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            assert device_found, "DUT not found in scan results"
            logger().info("initiating stop scanning")
            ble_client.interfaces.bluetooth.stop_scanning()
            time.sleep(5)
            logger().info("Initiating connection from remote device")
            conn_params = {"min_conn_interval": 0x04,
                           "max_conn_interval": 0x04,
                           "conn_latency": 0,
                           "supervision_timeout": 3200}

            ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                    min_conn_interval=conn_params["min_conn_interval"],
                                                    max_conn_interval=conn_params["max_conn_interval"],
                                                    conn_latency=conn_params["conn_latency"],
                                                    supervision_timeout=conn_params["supervision_timeout"])
            time.sleep(60)
            logger().info("Checking connection status of BLE")
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            ble_conn_config = bt_logs.read_ble_connection_params(conn_params)
            logger().info(f"**********{ble_conn_config} values in btmon logs")
            assert ble_conn_config["Status"] == "Success"
            assert (
                    ble_conn_config["max_conn_interval"]
                    == conn_params["max_conn_interval"]
            )
            time.sleep(5)
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
            m4_obj.start()
            time.sleep(2)
            pm_obj.start()
            pm_obj.wait_for_exit()
            m4_obj.wait_for_exit()
            time.sleep(10)
            logger().info("Initiating disconnection from remote device")
            ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
            time.sleep(5)
        except Exception as error:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************

# @pytest.mark.skip()
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES  | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
def test_ble_sdk_connect_with_200ms_0dBm_C20659(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections):
    """Verify ble connection with 200ms"""
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_connection_C20659_power{int(time.time())}.log",
    ) as bt_logs:
        try:
            logger().info(f"M4-TA secure handshake")
            wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            conn_params = {"min_conn_interval": 0xa0,
                           "max_conn_interval": 0xa0,
                           "conn_latency": 0,
                           "supervision_timeout": 3200}
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2048, ble_adv_int_max=2048,
                                                           ble_adv_channel_map=7)
            logger().info("Initiating power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")

            logger().info("Initiating scan from remote device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"
            scan_result = device_scan_result()
            device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                            bt_dut_address=bt_dut_address,
                                                                            adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            assert device_found, "DUT not found in scan results"
            logger().info("initiating stop scanning")
            ble_client.interfaces.bluetooth.stop_scanning()
            time.sleep(5)
            logger().info("Initiating connection from remote device")
            ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                    min_conn_interval=conn_params["min_conn_interval"],
                                                    max_conn_interval=conn_params["max_conn_interval"],
                                                    conn_latency=conn_params["conn_latency"],
                                                    supervision_timeout=conn_params["supervision_timeout"])
            time.sleep(60)
            logger().info("Checking connection status of BLE")
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            ble_conn_config = bt_logs.read_ble_connection_params(conn_params)
            logger().info(f"**********{ble_conn_config} values in btmon logs")
            assert ble_conn_config["Status"] == "Success"
            assert (
                    ble_conn_config["max_conn_interval"]
                    == conn_params["max_conn_interval"]
            )
            time.sleep(5)
            logger().info(f"found connection intervals of 200ms in btmon logs")
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
            m4_obj.start()
            time.sleep(2)
            pm_obj.start()
            pm_obj.wait_for_exit()
            m4_obj.wait_for_exit()
            time.sleep(10)
            logger().info("Initiating disconnection from remote device")
            ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
            time.sleep(5)

        except Exception as error:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************

