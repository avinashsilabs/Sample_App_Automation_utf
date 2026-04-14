import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.defaults import defaults
import string
import random
from random import randint
from utf.utils.iperf.iperf_utils import ping
import os
from utf.utils import print_dict
from utf.utf_config import UtfConfig
from utf.interfaces.power_meter.nrf_ppk2.nrf_power_profiler_mp import NRFPowerProfiler
from utf import UtfDatabaseProperties, TestUserPropertiesSource, UtfTestReport, TransformFileProperties


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in Wlan & coex mode for 2.4Ghz.
        2. Initiate the Scan from DUT.
        3. Initiate the connection with third party Access Point.
        4. Run the traffic TCP/UDP TX & RX.
        5. Verify the throughput of values TCP/UDP TX & RX values.  

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer@Silabs.com 
"""


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

    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, wifi_client=None,
                 net_perf_client=None, protocol=None, iteration_count=None, sl_collections=None, ping_count=None,
                 sniffer_filter=None, data_transfer=None, traffic_type=None, testcase=None, power_meter=None,
                 test_case_no=None, utf_constants=None, capture_time=40):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.testcase = testcase
        self.wifi_client = wifi_client
        self.iteration_count = iteration_count
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.data_transfer = data_transfer
        self.traffic_type = traffic_type
        self.test_case_no = test_case_no
        self.utf_constants = utf_constants
        self.device_ip = None
        self.dut_addr = None
        self.power_meter = power_meter
        self.capture_time = capture_time

    def run(self):
        if self.test_case_no == 20740 or self.test_case_no == 20750:
            transfer_type = 1
            protocol = 6
            throughput_type = 1
            size = 1460

        if self.test_case_no == 20741 or self.test_case_no == 20751:
            transfer_type = 1
            protocol = 6
            throughput_type = 3
            size = 1460

        if self.test_case_no == 20738 or self.test_case_no == 20748:
            transfer_type = 2
            protocol = 17
            throughput_type = 2
            size = 1470

        if self.test_case_no == 20739 or self.test_case_no == 20749:
            transfer_type = 2
            protocol = 17
            throughput_type = 4
            size = 1470

        logger().info("starting the sniffer again")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        #
        # self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
        #                                                          wifi_access_point=self.wifi_access_point,
        #                                                          associated=self.wifi_dut.interfaces.wifi.associated,
        #                                                          retry_count=3, ping_after_power_save=False,
        #                                                          ping_count=self.ping_count, power_save=False)

        # self.wifi_dut.interfaces.wifi.scan(channel=1, ssid=None)
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.join(enable_lwip=1, security='wpa2', ssid='WSDK-AUTOMATION', passphrase='12345678')
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.start_ip_lwip()
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.sl_net_up(mode='client')
        # for count in range(0, 3):
        #     try:
        #         self.wifi_dut.interfaces.wifi.sl_net_up(mode='client')
        #         time.sleep(2)
        #     except Exception as e:
        #         logger().info(
        #             f"\n\n **** Connection to Wi-Fi AP Failed....retrying for the {count + 1} iteration ****\n\n")
        #         logger().info(f"ERROR FOUND -> {str(e)}")
        #         reason = str(e)
        result = self.wifi_dut.interfaces.wifi.display_device_ip_lwip()
        time.sleep(2)
        logger().info(f"Device ip :{result}")
        dut_ip = self.wifi_dut.interfaces.wifi.get_device_ip(device_ip=result)
        logger().info(f"#######=====>>>>>>>{dut_ip}")
        self.wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter, capture_time=self.capture_time)
        pm_obj.start()
        time.sleep(10)
        if self.data_transfer:
            if self.traffic_type == "TX":
                self.iteration_count = self.iteration_count
                for i in range(0, self.iteration_count):
                    # starting iperf
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=dut_ip,
                                                                         protocol=self.protocol)
                    self.net_perf_client.interfaces.net_perf.start()
                    logger().info("sending data from DUT")
                    timeout = 40
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=dut_ip, remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                        timeout=timeout+2, host_tcp_ip_stack_enable=1)
                    # # get and print throughput
                    tp = self.net_perf_client.interfaces.net_perf.process_output()
                    assert tp is not None, "Throughput not found"
                    logger().info("data transfer successful")
                    time.sleep(5)
            if self.traffic_type == "RX":
                self.iteration_count = self.iteration_count
                for i in range(0, self.iteration_count):
                    # Iperf Client Started
                    if self.protocol == "UDP":
                        bandwidth = "68M"
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=dut_ip,
                                                                            protocol=self.protocol, bandwidth=bandwidth)
                        logger().info(f"***** start listening  ******")
                        self.net_perf_client.interfaces.net_perf.start()
                        timeout = 40
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            local_ip=dut_ip, remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                            async_socket=1, timeout=timeout + 2, host_tcp_ip_stack_enable=1)
                        logger().info("data received is successful")
                        time.sleep(3)

                    elif self.protocol == "TCP":
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip,
                                                                             device_ip=dut_ip,
                                                                             protocol=self.protocol)

                        def start_client():
                            time.sleep(1)
                            logger().info(f"***** start listening  ******")
                            self.net_perf_client.interfaces.net_perf.start()

                        client_thread1 = Thread(target=start_client, args=(), )
                        client_thread1.start()

                        # open socket and listen for data
                        timeout = 40
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            local_ip=dut_ip, remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                            async_socket=1, timeout=timeout + 2, host_tcp_ip_stack_enable=1)
                        client_thread1.join()
                        logger().info("data received is successful")
                        time.sleep(3)

        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        pm_obj.wait_for_exit()
        self.wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)


pytestmark = [pytest.mark.firmware_app("test_lwip_stack")]


@pytest.mark.start_state("wifi_dut", device='reset', wifi="net_init_client")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "ssid": 'WSDK-AUTOMATION', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}}
    }
)
@pytest.mark.test_src_map_id('C537890')
def test_wlan_standalone_tcp_tx_C537890(firmware_loader, wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                        net_perf_client, protocol, utf_constants, request, sl_collections,
                                        power_meter):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, power_meter=power_meter,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=20740,
                              iteration_count=iter_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip()
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "ssid": 'WSDK-AUTOMATION', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="net_init_client")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": 0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}}
    }
)
@pytest.mark.test_src_map_id('C537891')
def test_wlan_standalone_tcp_rx_C537891(firmware_loader, wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                        net_perf_client, protocol, utf_constants, request, sl_collections, power_meter):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, power_meter=power_meter,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20741,
                              iteration_count=iter_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "ssid": 'WSDK-AUTOMATION', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="net_init_client")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}}
    }
)
@pytest.mark.test_src_map_id('C537888')
def test_wlan_standalone_udp_tx_C537888(firmware_loader, wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                        net_perf_client, protocol, utf_constants, request, sl_collections, power_meter):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, power_meter=power_meter,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=20738,
                              iteration_count=iter_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "ssid": 'WSDK-AUTOMATION', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="net_init_client")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}}
    }
)
@pytest.mark.test_src_map_id('C537889')
def test_wlan_standalone_udp_rx_C537889(firmware_loader, wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                        net_perf_client, protocol, utf_constants, request, sl_collections, power_meter):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, power_meter=power_meter,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20739,
                              iteration_count=iter_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)