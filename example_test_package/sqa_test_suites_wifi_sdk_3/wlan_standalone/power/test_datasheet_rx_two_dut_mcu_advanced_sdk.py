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


class Active_TX_DUT_2(ThreadBase):
    def __init__(self, power=None, remote_wiseconnect3=None, rate=None, enable_11ax=0):
        self.power = power
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.rate = rate
        self.enable_11ax = enable_11ax

    def run(self):
        length=1000
        mode=1
        channel=1
        aggr_enable=0

        logger().info(f"setting the wireless antenna ")
        self.remote_wiseconnect3.interfaces.wifi.set_antenna(interface="client", antenna=5)
        
        logger().info(f"configuring DUT with power: {self.power}")

        self.remote_wiseconnect3.interfaces.wifi.sl_si91x_transmit_test_start(
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

        time.sleep(15)


class Recieve_Stats_DUT_1(ThreadBase):
    def __init__(self, wifi_dut=None):
        self.wifi_dut = wifi_dut
    
    def run(self):
        logger().info(f"Receive Test started.")
        self.wifi_dut.interfaces.wifi.start_statistic_report(interface="client", channel=11, max_stats_count=185)
        time.sleep(5)


class Active_RX_DUT_1(ThreadBase):
    def __init__(self, wifi_dut=None, power_meter=None):
        self.wifi_dut = wifi_dut
        self.power_meter = power_meter

    def run(self):
        
        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter)
        rx_stat = Recieve_Stats_DUT_1(wifi_dut=self.wifi_dut)

        self.wifi_dut.interfaces.wifi.set_antenna(interface="client", antenna=5)
        logger().info(f"setting the wireless antenna ")

        rx_stat.start()
        time.sleep(5)
        pm_obj.start()
        pm_obj.wait_for_exit()
        rx_stat.wait_for_exit()
        
        time.sleep(15)


# ********************************************************************************************************************

dut = UtfConfig.instance().defaults.get("dut", {})
logger().info(f"dut: {dut}")


# ********************************************************************************************************************

pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]

# ********************************************************************************************************************

# @pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.parametrize("power", [127])
@pytest.mark.parametrize("rate", [256])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}, "ble": {"count": 0, "stack_len": 2048}},
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
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)   
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    sapi=
    {        
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}, "ble": {"count": 0, "stack_len": 2048}},
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
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)              
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wlan_active_rx_ht_mcs0_C652604(firmware_loader, power_meter, remote_wiseconnect3,wifi_sniffer, request, wifi_dut, power, rate):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=11)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

    active_tx_obj = Active_TX_DUT_2(power=power, rate=rate, remote_wiseconnect3=remote_wiseconnect3)
    active_rx_obj = Active_RX_DUT_1(wifi_dut=wifi_dut, power_meter=power_meter)
    
    active_tx_obj.start()
    active_rx_obj.start()

    active_rx_obj.wait_for_exit()
    active_tx_obj.wait_for_exit()

    wifi_dut.interfaces.wifi.sl_si91x_transmit_test_stop()

    time.sleep(10)


# ********************************************************************************************************************


@pytest.mark.parametrize("power", [127])
@pytest.mark.parametrize("rate", [263])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}, "ble": {"count": 0, "stack_len": 2048}},
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
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)   
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    sapi=
    {        
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}, "ble": {"count": 0, "stack_len": 2048}},
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
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)                
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wlan_active_rx_ht_mcs7_C652605(firmware_loader, power_meter, remote_wiseconnect3,wifi_sniffer, request, wifi_dut, power, rate):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=11)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

    active_tx_obj = Active_TX_DUT_2(power=power, rate=rate, remote_wiseconnect3=remote_wiseconnect3)
    active_rx_obj = Active_RX_DUT_1(wifi_dut=wifi_dut, power_meter=power_meter)
    
    active_tx_obj.start()
    active_rx_obj.start()

    active_rx_obj.wait_for_exit()
    active_tx_obj.wait_for_exit()

    wifi_dut.interfaces.wifi.sl_si91x_transmit_test_stop()

    time.sleep(10)


# ********************************************************************************************************************


@pytest.mark.parametrize("power", [127])
@pytest.mark.parametrize("rate", [256])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}, "ble": {"count": 0, "stack_len": 2048}},
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
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)   
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    sapi=
    {        
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}, "ble": {"count": 0, "stack_len": 2048}},
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
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)                
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wlan_active_rx_he_mcs0_C652606(firmware_loader, power_meter, remote_wiseconnect3,wifi_sniffer, request, wifi_dut, power, rate):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=11)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

    active_tx_obj = Active_TX_DUT_2(power=power, rate=rate, enable_11ax=1, remote_wiseconnect3=remote_wiseconnect3)
    active_rx_obj = Active_RX_DUT_1(wifi_dut=wifi_dut, power_meter=power_meter)
    
    active_tx_obj.start()
    active_rx_obj.start()

    active_rx_obj.wait_for_exit()
    active_tx_obj.wait_for_exit()

    wifi_dut.interfaces.wifi.sl_si91x_transmit_test_stop()

    time.sleep(10)


# ********************************************************************************************************************


@pytest.mark.parametrize("power", [127])
@pytest.mark.parametrize("rate", [263])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}, "ble": {"count": 0, "stack_len": 2048}},
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
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)   
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    sapi=
    {        
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}, "ble": {"count": 0, "stack_len": 2048}},
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
        "region":1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)                 
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wlan_active_rx_he_mcs7_C652607(firmware_loader, power_meter, remote_wiseconnect3,wifi_sniffer, request, wifi_dut, power, rate):
    test_name = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(channel=11)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

    active_tx_obj = Active_TX_DUT_2(power=power, rate=rate, enable_11ax=1, remote_wiseconnect3=remote_wiseconnect3)
    active_rx_obj = Active_RX_DUT_1(wifi_dut=wifi_dut, power_meter=power_meter)
    
    active_tx_obj.start()
    active_rx_obj.start()

    active_rx_obj.wait_for_exit()
    active_tx_obj.wait_for_exit()

    wifi_dut.interfaces.wifi.sl_si91x_transmit_test_stop()

    time.sleep(10)


# ********************************************************************************************************************