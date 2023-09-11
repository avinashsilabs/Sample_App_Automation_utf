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
from utf.utils.iperf.iperf_utils import print_dict
import string
import random
from utf.utils.iperf.iperf_utils import ping


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


class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""
    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_client=None, \
                 net_perf_client=None, protocol=None, iteration_count=None, sl_collections=None, ping_count=None,
                 data_transfer=None, traffic_type=None, testcase=None,
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

    def run(self):
        if self.test_case_no == 20790:
            transfer_type = 1
            protocol = 6
            throughput_type = 3
            size = 1460

        if self.test_case_no == 20789:
            transfer_type = 2
            protocol = 17
            throughput_type = 4
            size = 1470

        if self.test_case_no == 20788:
            transfer_type = 1
            protocol = 6
            throughput_type = 1
            size = 1460

        if self.test_case_no == 20787:
            transfer_type = 2
            protocol = 17
            throughput_type = 2
            size = 1470

        logger().info("starting the sniffer again")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        ping_count = self.ping_count
        beacon = 100
        logger().info("********* configuring static ip to DUT *********")
        self.wifi_dut.interfaces.wifi.start_ip(static_ip="192.168.100.76", static_subnet='255.255.255.0',
                                          static_gateway='192.168.100.76')
        logger().info(" ********** Starting DUT as an AP ********* ")
        self.wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_C19444", security="WPA2", psk="12345678", channel=self.channel,
                                          dtim_beacon_count=self.dtim_period,
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

        if self.data_transfer:
            if self.traffic_type == "TX":
                self.iteration_count = self.iteration_count
                for i in range(0, self.iteration_count):
                    # starting iperf
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip,
                                                                         protocol=self.protocol)
                    self.net_perf_client.interfaces.net_perf.start()
                    logger().info("sending data from DUT")
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=device_ip, remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0)
                    # # get and print throughput
                    tp = self.net_perf_client.interfaces.net_perf.process_output()
                    assert tp is not None, "Throughput not found"
                    logger().info("data transfer successful")
                    time.sleep(3)
            if self.traffic_type == "RX":
                self.iteration_count = self.iteration_count
                for i in range(0, self.iteration_count):
                    if self.protocol == "UDP":
                        bandwidth = "68M"
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip,
                                                                             protocol=self.protocol, bandwidth=bandwidth)
                    else:
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip,
                                                                             protocol=self.protocol)

                    self.net_perf_client.interfaces.net_perf.start()

                    logger().info("receiving data from Host")
                    # open socket and listen for data
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                        local_ip=device_ip, remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0)
                    logger().info("data received is successful")
                    time.sleep(3)
        logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
        self.wifi_client.interfaces.wifi.leave()
        self.wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
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
def test_wlan_sdk_ap_alone_device_as_server_tcp_rx_c20790(wifi_sniffer, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, dtim_period, channel):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20790,
                              iteration_count=iter_count, channel=channel
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
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
def test_wlan_sdk_ap_alone_device_as_server_udp_rx_c20789(wifi_sniffer, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, dtim_period, channel):
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


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
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
def test_wlan_sdk_ap_alone_device_as_client_tcp_tx_c20788(wifi_sniffer, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, channel, dtim_period):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=20788,
                              iteration_count=iter_count, channel=channel
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("dtim_period", [1])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
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
def test_wlan_sdk_ap_alone_device_as_client_udp_tx_c20787(wifi_sniffer, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, channel, dtim_period):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=20787,
                              iteration_count=iter_count, channel=channel
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)