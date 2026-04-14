import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xExtCustomFeatureBitMap
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
from utf.utils.logger import get_logger
from utf.utils.defaults import defaults
from utf.utils import print_dict
import string
import random
from utf.utils.iperf.iperf_utils import ping
import os
from utf.utils import print_dict
from utf.utf_config import UtfConfig
from utf.interfaces.power_meter.nrf_ppk2.nrf_power_profiler_mp import NRFPowerProfiler
from utf import UtfDatabaseProperties, TestUserPropertiesSource, UtfTestReport, TransformFileProperties


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in AP mode for 2.4Ghz.
        2. Initiate the Scan from DUT.
        3. Initiate the connection with third party Raspi Client.
        4. Run the traffic TCP/UDP TX & RX.
        5. Verify the throughput of values TCP/UDP TX & RX values.  

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Raspi Client

    Author: Benazeer K 
"""


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


class Power_Device:

    def __init__(self) -> None:
        pass

    def power_measurement(power_device=None, power_meter=None, dtim=None, capture_time=45):

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

        # if dut == "si917_ncp_sl_wifi":
        #     self.power_meter.interfaces.power_meter.set_output_channels_settings(
        #         [{"channel": "1", "emulation_mode": "Current Measure", "trace_current": True, "trace_voltage": False,
        #           "trace_power": False}])
        #
        # else:
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


class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""
    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_client=None, \
                 net_perf_client=None, protocol=None, iteration_count=None, sl_collections=None, ping_count=None,
                 data_transfer=None, traffic_type=None, testcase=None, power_meter=None, capture_time=None,
                 test_case_no=None, channel=None, dtim_period=None, utf_constants=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.testcase = testcase
        self.iteration_count = iteration_count
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.data_transfer = data_transfer
        self.traffic_type = traffic_type
        self.test_case_no = test_case_no
        self.dut_mac_address = None
        self.channel = channel
        self.utf_constants = utf_constants
        self.dtim_period = dtim_period
        self.power_meter = power_meter
        self.capture_time =capture_time

    def run(self):
        logger().info("starting the sniffer capture")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        ping_count = self.ping_count
        beacon = 100
        ht_caps =1
        logger().info("********* configuring static ip to DUT *********")
        self.wifi_dut.interfaces.wifi.start_ip(static_ip="192.168.100.76", static_subnet='255.255.255.0',
                                          static_gateway='192.168.100.76')
        logger().info(" ********** Starting DUT as an AP ********* ")
        self.wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_C19444", security="WPA2", psk="12345678", channel=self.channel,
                                          dtim_beacon_count=self.dtim_period, ht_caps=ht_caps,
                                          beacon_interval=beacon)
        logger().info("********** Raspberry pi Client connected to DUT AP*********")
        self.wifi_client.interfaces.wifi.join()
        time.sleep(10)

        logger().info(f"Initiating wlan ping from client '{self.wifi_client.name}' to DUT")
        client_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Client IP **********: {client_ip}")

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Host IP is: {host_ip}")

        device_ip = self.wifi_client.interfaces.wifi.client_gateway_ip
        logger().info(f"********* Device IP **********: {device_ip}")

        status = ping(device_ip, ping_count)
        assert status == True, f"Ping failed"

        assert self.wifi_client.interfaces.wifi.ping(server_ip=device_ip), f"ping failed"

        self.wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)
        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter, capture_time=self.capture_time)
        pm_obj.start()
        time.sleep(10)

        if self.test_case_no == 20790:
            protocols = ["TCP"]
            traffic_types = ["RX"]
            for protocol in protocols:
                for traffic_type in traffic_types:
                    self.wifi_dut.interfaces.wifi.set_socket_config()
                    self.sl_collections.run_traffic(
                        wifi_dut=self.wifi_dut,
                        net_perf_client=self.net_perf_client,
                        protocol=protocol,
                        device_ip=device_ip,
                        host_ip=host_ip,
                        timeout=35,
                        traffic_type=traffic_type,
                    )
        if self.test_case_no == 20789:
            protocols = ["UDP"]
            traffic_types = ["RX"]
            for protocol in protocols:
                for traffic_type in traffic_types:
                    self.sl_collections.run_traffic(
                        wifi_dut=self.wifi_dut,
                        net_perf_client=self.net_perf_client,
                        protocol=protocol,
                        device_ip=device_ip,
                        host_ip=host_ip,
                        timeout=35,
                        traffic_type=traffic_type,
                        async_socket=1
                    )
        if self.test_case_no == 20788:
            protocols = ["TCP"]
            traffic_types = ["TX"]
            for protocol in protocols:
                for traffic_type in traffic_types:
                    self.sl_collections.run_traffic(
                        wifi_dut=self.wifi_dut,
                        net_perf_client=self.net_perf_client,
                        protocol=protocol,
                        device_ip=device_ip,
                        host_ip=host_ip,
                        timeout=35,
                        traffic_type=traffic_type,
                    )
        if self.test_case_no == 20787:
            protocols = ["UDP"]
            traffic_types = ["TX"]
            for protocol in protocols:
                for traffic_type in traffic_types:
                    self.sl_collections.run_traffic(
                        wifi_dut=self.wifi_dut,
                        net_perf_client=self.net_perf_client,
                        protocol=protocol,
                        device_ip=device_ip,
                        host_ip=host_ip,
                        timeout=35,
                        traffic_type=traffic_type,
                    )
        logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
        self.wifi_client.interfaces.wifi.leave()
        pm_obj.wait_for_exit()
        time.sleep(2)
        self.wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100, "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.test_src_map_id('C20754')
def test_wlan_sdk_ap_alone_with_480K_tcp_rx_c20754(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, power_meter,
                                                   net_perf_client, protocol, utf_constants, request, sl_collections,
                                                   dtim_period, channel):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20790,
                              iteration_count=iter_count, channel=channel, power_meter=power_meter
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100, "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.test_src_map_id('C20755')
def test_wlan_sdk_ap_alone_with_480K_udp_rx_c20755(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, power_meter,
                                                   net_perf_client, protocol, utf_constants, request, sl_collections,
                                                   dtim_period, channel):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20789,
                              iteration_count=iter_count, channel=channel
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100, "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.test_src_map_id('C20752')
def test_wlan_sdk_ap_alone_with_480K_tcp_tx_c20752(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, power_meter,
                                                   net_perf_client, protocol, utf_constants, request, sl_collections,
                                                   channel, dtim_period):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=20788,
                              iteration_count=iter_count, channel=channel, power_meter=power_meter
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100, "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.test_src_map_id('C20753')
def test_wlan_sdk_ap_alone_with_480K_udp_tx_c20753(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, power_meter,
                                                   net_perf_client, protocol, utf_constants, request, sl_collections,
                                                   channel, dtim_period):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=20787,
                              iteration_count=iter_count, channel=channel, power_meter=power_meter
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_416K_M4SS_256K")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100, "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.test_src_map_id('C532965')
def test_wlan_sdk_ap_alone_with_416K_tcp_rx_C532965(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, power_meter,
                                                    net_perf_client, protocol, utf_constants, request, sl_collections,
                                                    dtim_period, channel):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20790,
                              iteration_count=iter_count, channel=channel, power_meter=power_meter
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_416K_M4SS_256K")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100, "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.test_src_map_id('C532963')
def test_wlan_sdk_ap_alone_with_416K_udp_rx_C532963(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, power_meter,
                                                    net_perf_client, protocol, utf_constants, request, sl_collections,
                                                    dtim_period, channel):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20789,
                              iteration_count=iter_count, channel=channel, power_meter=power_meter
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_416K_M4SS_256K")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100, "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.test_src_map_id('C532964')
def test_wlan_sdk_ap_alone_with_416K__tcp_tx_C532964(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, power_meter,
                                                     net_perf_client, protocol, utf_constants, request, sl_collections,
                                                     channel, dtim_period):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=20788,
                              iteration_count=iter_count, channel=channel, power_meter=power_meter
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_416K_M4SS_256K")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100, "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.test_src_map_id('C532962')
def test_wlan_sdk_ap_alone_with_416K_udp_tx_C532962(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, power_meter,
                                                    net_perf_client, protocol, utf_constants, request, sl_collections,
                                                    channel, dtim_period):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=20787,
                              iteration_count=iter_count, channel=channel, power_meter=power_meter
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100, "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.test_src_map_id('C532969')
def test_wlan_sdk_ap_alone_with_320K_tcp_rx_C532969(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, power_meter,
                                                    net_perf_client, protocol, utf_constants, request, sl_collections,
                                                    dtim_period, channel):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20790,
                              iteration_count=iter_count, channel=channel, power_meter=power_meter
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100, "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.test_src_map_id('C532967')
def test_wlan_sdk_ap_alone_with_320K_udp_rx_C532967(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, power_meter,
                                                    net_perf_client, protocol, utf_constants, request, sl_collections,
                                                    dtim_period, channel):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20789,
                              iteration_count=iter_count, channel=channel, power_meter=power_meter
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100, "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.test_src_map_id('C532968')
def test_wlan_sdk_ap_alone_with_320K_tcp_tx_C532968(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, power_meter,
                                                    net_perf_client, protocol, utf_constants, request, sl_collections,
                                                    channel, dtim_period):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=20788,
                              iteration_count=iter_count, channel=channel, power_meter=power_meter
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100, "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.test_src_map_id('C532966')
def test_wlan_sdk_ap_alone_with_320Kudp_tx_C532966(firmware_loader, wifi_sniffer, wifi_client, wifi_dut, power_meter,
                                                   net_perf_client, protocol, utf_constants, request, sl_collections,
                                                   channel, dtim_period):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=20787,
                              iteration_count=iter_count, channel=channel, power_meter=power_meter
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
