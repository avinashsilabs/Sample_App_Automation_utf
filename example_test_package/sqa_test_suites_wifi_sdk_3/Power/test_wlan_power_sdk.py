import pytest
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
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

class Power_Device:

    def __init__(self) -> None:
        pass
        
    def power_measurement(power_device=None, power_meter=None, dtim=None):
        
        if power_device == "keysight_benchvue_power_analyzer_win_wcf":
            power_obj = power_number_output(power_meter=power_meter, dtim=dtim)
        elif power_device == "nrf_ppk2_device":
            power_obj = ppk_power_number_output(power_meter=power_meter)
        power_obj.get_power_value()


class power_number_output():
    def __init__(self, power_meter=None, dtim=None):
        super().__init__()
        self.power_meter = power_meter
        self.dtim = dtim

    def __print_throughput(self, throughput: dict):
        if throughput is not None:
            print_dict("##     ", throughput)

    def get_power_value(self):
        if self.dtim:
            # Init power meter by specifying module name as datalogger or scope
            logger().info(f"initiating power meter wih dtim")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log_{self.dtim}")
        else:
            logger().info(f"initiating power meter")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log")
        # Init power meter module

        self.power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
        # set power meter out put channels
        logger().info(f"setting output channels")
        self.power_meter.interfaces.power_meter.set_output_channels_settings(
            [{"channel": "1", "emulation_mode": "Current Measure", "trace_current": True, "trace_voltage": False,
              "trace_power": False}])
        # power_meter.interfaces.power_meter.set_output_channels(["1"])
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

    def __init__(self, remote_socket=None, wifi_dut=None, wifi_access_point=None, device2_ip=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.device2_ip = device2_ip
        self.remote_socket = remote_socket
        
    def run(self):
        data_size = 42
        data = "tcpdatastartedtcpdatastartedtcpdatastarted"
        no_of_iterations = 5
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
        for i in range(1, no_of_iterations):
            self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock_id,
                                                        data=data)
            data = self.remote_socket.interfaces.socket.recv_data_tcp(data_size)
            time.sleep(55)
        time.sleep(10)
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
    def __init__(self, wifi_dut=None, deep_sleep_without_ret=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.deep_sleep_without_ret = deep_sleep_without_ret

    def run(self):
        logger().info(f"Enabling M4 power save")
        if self.deep_sleep_without_ret:
            self.wifi_dut.interfaces.wifi.m4_power_manager_deep_sleep(state=0,
                                                                      sleep_time=100000)
        else:
            self.wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=100000)
            
class Power_Measurement_Thread(ThreadBase, Power_Device):


    def __init__(self, power_meter=None):
        super().__init__()
        Power_Device().__init__()
        self.power_meter = power_meter
	
    def run(self):
        logger().info(f"Starting Power Capture")
        self.power_device = UtfConfig.instance().defaults.get("power_meter", {})
        Power_Device.power_measurement(power_device=self.power_device, power_meter=self.power_meter)

class StandBy_Associated:
    def __init__(self, dtim=None, wifi_dut=None, wifi_access_point=None, sl_collections=None, power_meter=None):
        self.dtim = dtim
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.wifi_access_point=wifi_access_point
        self.power_meter = power_meter

    def execute(self):
        logger().info(f"M4-TA secure handshake")
        self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)

        time.sleep(2)

        self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface = 'client',
            join_feature_bitmap = Si91xJoinFeatureBitMap.Default
        )
        wlan_obj = WlanThread(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, dtim=self.dtim,
                            sl_collections=self.sl_collections)
        m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut)
        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        time.sleep(2)

        logger().info(f"Setting filter broadcast command")
        self.wifi_dut.interfaces.wifi.set_filter_broadcast()

        time.sleep(2)

        logger().info(f"Enabling TA power save")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save", dtim_aligned_type=1)
        time.sleep(2)

        m4_obj.start()
        time.sleep(2)
        pm_obj.start()
        pm_obj.wait_for_exit()
        m4_obj.wait_for_exit()

        time.sleep(10)

class Active_TX:
    def __init__(self, power=None, wifi_dut=None, power_meter=None):
        self.power = power
        self.wifi_dut = wifi_dut
        self.power_meter = power_meter

    def execute(self):
        rate = 139
        length=1000
        mode=1
        channel=1
        aggr_enable=0

        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter)

        self.wifi_dut.interfaces.wifi.set_antenna(interface="client", antenna=5)
        logger().info(f"setting the wireless antenna ")

        logger().info(f"configuring dut with diff power:{self.power}")

        self.wifi_dut.interfaces.wifi.sl_si91x_transmit_test_start(
                enable= 1,
                power= self.power,
                rate=rate,
                length=length,
                mode=mode,
                channel=channel,
                aggr_enable=aggr_enable,
                )
        logger().info(f"Transmit Test started.")
        time.sleep(5)

        pm_obj.start()
        pm_obj.wait_for_exit()
        
        self.wifi_dut.interfaces.wifi.sl_si91x_transmit_test_stop()

        time.sleep(15)
        



# ********************************************************************************************************************


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
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_standby_associated_DTIM_1_c20638(power_meter, wifi_access_point, wifi_dut, sl_collections, dtim):
    stdby_obj=StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections, power_meter=power_meter)
    stdby_obj.execute()


 # ********************************************************************************************************************


@pytest.mark.parametrize("dtim", [3])
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
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_standby_associated_DTIM_3_c20631(power_meter, wifi_access_point, wifi_dut, sl_collections, dtim):
    stdby_obj=StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections, power_meter=power_meter)
    stdby_obj.execute()


# ********************************************************************************************************************


@pytest.mark.parametrize("dtim", [10])
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
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_standby_associated_DTIM_10_c20632(power_meter, wifi_access_point, wifi_dut, sl_collections, dtim):
    stdby_obj=StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections, power_meter=power_meter)
    stdby_obj.execute()

   
# ********************************************************************************************************************


@pytest.mark.parametrize("power", [10])
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
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region_code": Si91xRegionCode.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_active_tx_10dBm_c20643(power_meter, wifi_dut, power):
    active_obj = Active_TX(power=power, wifi_dut=wifi_dut, power_meter=power_meter)
    active_obj.execute()
    

# ********************************************************************************************************************


@pytest.mark.parametrize("power", [20])
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
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region_code": Si91xRegionCode.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_active_tx_20dBm_20644(power_meter, wifi_dut, power):
    active_obj = Active_TX(power=power, wifi_dut=wifi_dut, power_meter=power_meter)
    active_obj.execute()


# ********************************************************************************************************************


@pytest.mark.parametrize("dtim", [255])
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
        "bt_features" : 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features" : 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1, "dtim": 200,
                                               "beacon_interval": 300})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_standby_associated_sleep_c20639(power_meter, wifi_access_point, wifi_dut, dtim, sl_collections):
    stdby_obj=StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections, power_meter=power_meter)
    stdby_obj.execute()

    
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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wlan_power_save_without_ram_ret_c20640(power_meter, wifi_dut):
            
    logger().info(f"M4-TA secure handshake")
    wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5,xtal_enable=1)
    time.sleep(2)

    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut, deep_sleep_without_ret=1)
    pm_obj = Power_Measurement_Thread(power_meter=power_meter)

    logger().info(f"Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save")
    time.sleep(2)

    m4_obj.start()
    time.sleep(2)
    pm_obj.start() 
    pm_obj.wait_for_exit()
    m4_obj.wait_for_exit()

    time.sleep(15)


# ********************************************************************************************************************
