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
from utf.utils.defaults import defaults
import string
import random
from utf.utils.iperf.iperf_utils import ping


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

    Author: Benazeer K 
"""


class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""

    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_access_point=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, iteration_count=None, sl_collections=None, ping_count=None,
                 sniffer_filter=None, data_transfer=None, traffic_type=None, testcase=None, bt_dut=None,
                 test_case_no=None, ble_client=None, ble_conn=None, utf_constants=None, mode=None, ble_data_transfer=None):
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
        self.bt_dut = bt_dut
        self.ble_client = ble_client
        self.ble_conn = ble_conn
        self.utf_constants = utf_constants
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.dut_addr = None
        self.mode = mode
        self.ble_data_transfer = ble_data_transfer

    def run(self):
        if self.test_case_no == 20740:
            transfer_type = 1
            protocol = 6
            throughput_type = 1
            size = 1460

        if self.test_case_no == 20741:
            transfer_type = 1
            protocol = 6
            throughput_type = 3
            size = 1460

        if self.test_case_no == 20738:
            transfer_type = 2
            protocol = 17
            throughput_type = 2
            size = 1470

        if self.test_case_no == 20739:
            transfer_type = 2
            protocol = 17
            throughput_type = 4
            size = 1470

        logger().info("starting the sniffer again")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        if self.ble_conn:
            conn_params = {
                "min_conn_interval": self.utf_constants.get("min_conn_interval"),
                "max_conn_interval": self.utf_constants.get("max_conn_interval"),
                "conn_latency": 0,
                "supervision_timeout": self.utf_constants.get("supervision_timeout")}
            logger().info("Initiate ble service in DUT")
            bt_dut_address = self.bt_dut.interfaces.bluetooth.ble_start()
            assert bt_dut_address, "unable to fetch dut bd address...."

            logger().info("Set DUT in advertise mode")
            self.bt_dut.interfaces.bluetooth.ble_start_advertising()

            logger().info("Start smp scan from the remote device")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(5)
            logger().info("stop scanning ....")
            self.ble_client.interfaces.bluetooth.stop_scanning()

            # See that we found our device
            logger().info("Check the dut is listed...")
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert self.bt_dut.interfaces.bluetooth.ble_address in found_devices

            self.ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                         min_conn_interval=conn_params["min_conn_interval"],
                                                         max_conn_interval=conn_params["max_conn_interval"],
                                                         conn_latency=conn_params["conn_latency"],
                                                         supervision_timeout=conn_params["supervision_timeout"])

            assert bt_dut_address, "unable to connect to the given address"
            time.sleep(12)

        if self.ble_data_transfer:
            logger().info(f"BLE Data Transfer going to start")
            if self.mode == "ble_master":
                logger().info(f"Start DUT")
                bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
                assert bt_dut_address is not None
                logger().info(f"Start ble client")
                ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
                assert ble_client_address is not None
                time.sleep(10)
                logger().info(f"Start scanning and connect to ble client")
                self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=30)
                timeout = 120
                logger().info(f"connect")
                self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=timeout)

            if self.mode == "ble_slave":
                logger().info(f" this thread used for sta+ble as a slave")
                logger().info(f"Set up DUT for BLE advertising")
                ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
                assert ble_dut_address is not None
                self.wifi_dut.interfaces.wifi.ble_start_advertising()
                logger().info(f"Begin Scanning for BLE devices")
                bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
                assert bt_client_address is not None
                time.sleep(5)
                self.ble_client.interfaces.bluetooth.stop_scanning()
                logger().info(f"See that we found our device")
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
                assert (
                        found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                        == self.wifi_dut.interfaces.wifi.ble_advertising_data
                )
                self.ble_client.interfaces.bluetooth.connect(ble_dut_address)
                logger().info(f"Connection success")

        self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                 wifi_access_point=self.wifi_access_point,
                                                                 associated=self.wifi_dut.interfaces.wifi.associated,
                                                                 retry_count=3, ping_after_power_save=False,
                                                                 ping_count=self.ping_count, power_save=False)
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        if self.data_transfer:
            if self.traffic_type == "TX":
                self.iteration_count = self.iteration_count
                for i in range(0, self.iteration_count):
                    # starting iperf
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=
                    self.dut_addr['device_ip'], protocol=self.protocol)
                    self.net_perf_client.interfaces.net_perf.start()
                    logger().info("sending data from DUT")
                    timeout = 40
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                        timeout=timeout+2)
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
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                        self.dut_addr['device_ip'], protocol=self.protocol, bandwidth=bandwidth)
                        logger().info(f"***** start listening  ******")
                        self.net_perf_client.interfaces.net_perf.start()
                        timeout = 40
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                            async_socket=1, timeout=timeout + 2)
                        logger().info("data received is successful")
                        time.sleep(3)

                    elif self.protocol == "TCP":
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                        self.dut_addr['device_ip'], protocol=self.protocol)

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
                                                        local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                        async_socket=1, timeout=timeout + 2)
                    client_thread1.join()
                    logger().info("data received is successful")
                    time.sleep(3)

        if self.ble_conn:
            self.bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
            time.sleep(2)

        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        self.wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}}
    }
)
def test_wlan_standalone_tcp_tx_416_256K_C146711(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=20740,
                              iteration_count=iter_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
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
def test_wlan_standalone_tcp_rx_416_256K_C146712(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
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
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}}
    }
)
def test_wlan_standalone_udp_tx_416_256K_c20738(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
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
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}}
    }
)
def test_wlan_standalone_udp_rx_416_256K_c20739(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20739,
                              iteration_count=iter_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'n'})
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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
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
def test_wlan_standalone_tcp_tx_with_416_256K_11n_C146715(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=20740,
                              iteration_count=iter_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'n'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
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
def test_wlan_standalone_tcp_rx_416_256K_11n_C146716(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20741,
                              iteration_count=iter_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}}

    }
)
def test_wlan_ble_connected_tcp_tx_416_256K_c20746(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="TX", test_case_no=20740,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}}

    }
)
def test_wlan_ble_connected_tcp_rx_416_256K_c20747(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="RX", test_case_no=20741,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


# @pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}}

    }
)
def test_wlan_ble_connected_udp_tx_416_256K_c20744(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="TX", test_case_no=20738,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}}

    }
)
def test_wlan_ble_connected_udp_rx_416_256K_c20745(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="RX", test_case_no=20739,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



