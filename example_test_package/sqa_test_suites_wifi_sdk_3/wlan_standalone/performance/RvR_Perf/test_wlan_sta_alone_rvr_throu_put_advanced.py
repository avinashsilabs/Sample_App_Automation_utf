import time
import pytest
from random import randint
import random
import string
from utf.utf_config import UtfConfig
import re
from utf.interfaces.wifi import SecurityMode
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf.interfaces.wifi import WlanError
from utf.utils import print_dict
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes,\
    Si91xExtCustomFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xRegion, Si91xRegionCode, Si91xModuleType, Si91xJoinFeatureBitMap
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI


"""Test Author = Benazeer K
        1. Initiate the Pri-DUT as AP
        2. Initiate connection from Sec-DUT
        3. Initiate ping from the Sec-DUT
        4. Get the current signal strength of STA
        5. Do the attenuation from attenuator from 0 to 60
        6. while attenuation get all RSSI Values
        7. Disconnect the wifi client
setup requirement:
        1. Dual DUT(required 2 Soc917)                                        
        2. Attenuator 50PA-500
"""


def logger():
    return get_logger(__name__)


class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity with RSSI levels """

    def __init__(self, wifi_dut=None, rf_attenuator=None, test_case_id=None, test_case_no=None, data_transfer=None,
                 set_att_count=None, sl_collections=None, utf_constants=None, wifi_sniffer=None, wifi_client=None,
                 wifi_access_point=None, net_perf_client=None, protocol=None, traffic_type=None, testcase=None,
                 ping_count=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.data_transfer = data_transfer
        self.rf_attenuator = rf_attenuator
        self.test_case_id = test_case_id
        self.set_att_count = set_att_count
        self.sl_collections = sl_collections
        self.utf_constants = utf_constants
        self.test_case_no = test_case_no
        self.wifi_sniffer = wifi_sniffer
        self.wifi_client = wifi_client
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.traffic_type = traffic_type
        self.testcase = testcase
        self.ping_count = ping_count

    def run(self):
        logger().info("starting the sniffer again")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
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

        set_db_value = 0
        self.wifi_dut.interfaces.wifi.set_attenuator(self.rf_attenuator, att_channel=1, db_value=set_db_value)
        time.sleep(10)
        self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                 wifi_access_point=self.wifi_access_point,
                                                                 associated=self.wifi_dut.interfaces.wifi.associated,
                                                                 retry_count=3, ping_after_power_save=False,
                                                                 ping_count=self.ping_count, power_save=False)
        self.wifi_dut.interfaces.wifi.poll_signal_strength()
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        set_att_count = self.utf_constants.get("set_att_count")
        for set_db_value in range(set_att_count):
            self.wifi_dut.interfaces.wifi.set_attenuator(self.rf_attenuator, att_channel=1, db_value=set_db_value)
            time.sleep(10)
            self.remote_wiseconnect3.interfaces.wifi.poll_signal_strength()
            time.sleep(5)
            if self.data_transfer:
                if self.traffic_type == "TX":
                        # starting iperf
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                         device_ip=self.dut_addr['device_ip'],
                                                                         protocol=self.protocol)
                    self.net_perf_client.interfaces.net_perf.start()
                    logger().info("sending data from DUT")
                    timeout = 40
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                        timeout=timeout + 2)
                    # # get and print throughput
                    tp = self.net_perf_client.interfaces.net_perf.process_output()
                    assert tp is not None, "Throughput not found"
                    logger().info("data transfer successful")
                    time.sleep(5)
                if self.traffic_type == "RX":
                        # Iperf Client Started
                    if self.protocol == "UDP":
                        bandwidth = "68M"
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip,
                                                                             device_ip=self.dut_addr['device_ip'],
                                                                             protocol=self.protocol,
                                                                             bandwidth=bandwidth)
                        logger().info(f"***** start listening  ******")
                        self.net_perf_client.interfaces.net_perf.start()
                        timeout = 40
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type,
                                                            protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            size=size, ttl=30, throughput_type=throughput_type,
                                                            qos=0,
                                                            async_socket=1, timeout=timeout + 2)
                        logger().info("data received is successful")
                        time.sleep(3)

                    elif self.protocol == "TCP":
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip,
                                                                             device_ip=self.dut_addr['device_ip'],
                                                                             protocol=self.protocol)

                        def start_client():
                            time.sleep(1)
                            logger().info(f"***** start listening  ******")
                            self.net_perf_client.interfaces.net_perf.start()

                        client_thread1 = Thread(target=start_client, args=(), )
                        client_thread1.start()

                        # open socket and listen for data
                        timeout = 40
                        self.wifi_dut.interfaces.wifi.set_socket_config()
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type,
                                                            protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            size=size, ttl=30, throughput_type=throughput_type,
                                                            qos=0,
                                                            async_socket=1, timeout=timeout + 2)
                        client_thread1.join()
                        logger().info("data received is successful")
                        time.sleep(3)
        logger().info(f"STA is going to leave AP")
        self.wifi_dut.interfaces.wifi.leave()


pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.wifi_access_point("static_ap")
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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
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
def test_wlan_sta_alone_rvr_tcp_tx_C402883(firmware_loader, wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                           net_perf_client, protocol, utf_constants, request, sl_collections,
                                           rf_attenuator):
    ping_count = utf_constants.get("ping_count")
    set_att_count = utf_constants.get("set_att_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, ping_count=ping_count,
                              data_transfer=True, traffic_type="TX", test_case_no=20740, rf_attenuator=rf_attenuator,
                              set_att_count=set_att_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.wifi_access_point("static_ap")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.SSL,
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
def test_wlan_sta_alone_rvr_tcp_rx_C402884(firmware_loader, wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                          net_perf_client, protocol, utf_constants, request, sl_collections,
                                           rf_attenuator):
    ping_count = utf_constants.get("ping_count")
    set_att_count = utf_constants.get("set_att_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, ping_count=ping_count,
                              data_transfer=True, traffic_type="RX", test_case_no=20741, rf_attenuator=rf_attenuator,
                              set_att_count=set_att_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.wifi_access_point("static_ap")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
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
def test_wlan_sta_alone_rvr_udp_tx_C402885(firmware_loader, wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                          net_perf_client, protocol, utf_constants, request, sl_collections,
                                           rf_attenuator):
    ping_count = utf_constants.get("ping_count")
    set_att_count = utf_constants.get("set_att_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, ping_count=ping_count,
                              data_transfer=True, traffic_type="TX", test_case_no=20738, rf_attenuator=rf_attenuator,
                              set_att_count=set_att_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.wifi_access_point("static_ap")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
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
def test_wlan_sta_alone_rvr_udp_rx_C402886(firmware_loader, wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                           net_perf_client, protocol, utf_constants, request, sl_collections,
                                           rf_attenuator):
    ping_count = utf_constants.get("ping_count")
    set_att_count = utf_constants.get("set_att_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, ping_count=ping_count,
                              data_transfer=True, traffic_type="RX", test_case_no=20739, rf_attenuator=rf_attenuator,
                              set_att_count=set_att_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)