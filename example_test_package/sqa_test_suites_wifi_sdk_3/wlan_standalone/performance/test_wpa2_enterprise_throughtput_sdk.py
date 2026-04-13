import time
import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xJoinFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, DeviceConstants
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger
from random import randint


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9117
        1. Configuration of DUT in 2G : B/G/N/AX
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Enable the power save mode in DUT & BLE
        6. Stop the sniffer  
        7. Analyizing all sniffer capture packets for wpa3 functionality
    setup requirement:
        1. DUT(RS9117)
        2. WSDK 3.0 Board
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer K@silabs
"""


class WifiConnectionThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, time_period=None, sniffer_filter=None,
                 data=None, ping_count=None, data_transfer=True, test_name=None, sl_collections=None, wifi_client=None,
                 traffic_type=None, dut_leave=True, protocol=None, net_perf_client=None, test_case_no=None,
                 iteration_count=None, eap_type=None, dut_addr=None, ssl_data_transfer=None, ssl_traffic_type=None,
                 ssl_server=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.time_period = time_period
        self.data = data
        self.ping_count = ping_count
        self.protocol = protocol
        self.device_ip = None
        self.iteration_count = iteration_count
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.traffic_type = traffic_type
        self.ssl_traffic_type = ssl_traffic_type
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.dut_leave = dut_leave
        self.test_name = test_name
        self.eap_type = eap_type
        self.dut_addr = dut_addr
        self.ssl_server = ssl_server
        self.ssl_data_transfer = ssl_data_transfer

    def run(self):
        try:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

            if self.test_case_no == 34513:
                transfer_type = 1
                protocol = 6
                throughput_type = 3
                size = 1460

            if self.test_case_no == 34515:
                transfer_type = 2
                protocol = 17
                throughput_type = 4
                size = 1470

            if self.test_case_no == 34512:
                transfer_type = 1
                protocol = 6
                throughput_type = 1
                size = 1460

            if self.test_case_no == 34514:
                transfer_type = 2
                protocol = 17
                throughput_type = 2
                size = 1470

            # self.wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
            # self.wifi_access_point.interfaces.wifi.start_ap()
            time.sleep(5)
            self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=self.wifi_access_point.interfaces.wifi.ssid)
            self.wifi_dut.interfaces.wifi.set_eap_credentials()
            if self.eap_type == "tls" or self.eap_type == "ttls" or self.eap_type == "peap" or self.eap_type == "fast":
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                   wifi_access_point=self.wifi_access_point,
                                                   eap_type=self.eap_type, power_save=False,
                                                   ping_after_power_save=False)
                # self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                #                               passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                #                               security="wpa3_enterprise", uid="user1", enc=self.eap_type)
                # self.wifi_dut.interfaces.wifi.start_ip()

            self.dut_addr = {'dut_mac_address': self.wifi_dut.interfaces.wifi.get_mac_address(),
                                 'device_ip': self.wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)}
            logger().info(f"DUT MAC ADDRESS :  {self.dut_addr['dut_mac_address']}")
            logger().info(f"DUT ip: {self.dut_addr['device_ip']}")
            status = self.sl_collections.ping(device_ip=self.dut_addr['device_ip'], ping_count=10)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
            time.sleep(2)
            self.wifi_dut.interfaces.wifi.switch_host_frequency()
            time.sleep(2)
            if self.data_transfer:
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                if self.traffic_type == "TX":
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
                        time.sleep(3)
                if self.traffic_type == "RX":
                    # self.iteration_count = self.iteration_count
                    for i in range(0, self.iteration_count):
                        # Iperf Client Started
                        if self.protocol == "UDP":
                            bandwidth = "68M"
                            self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                            self.dut_addr['device_ip'], protocol=self.protocol, bandwidth=bandwidth)
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
                            self.wifi_dut.interfaces.wifi.set_socket_config()
                            self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                                local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                                local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                                remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                                size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                                async_socket=1, timeout=timeout + 2)
                            client_thread1.join()
                            logger().info("data received is successful")
                            time.sleep(3)

            if self.ssl_data_transfer:
                if self.ssl_traffic_type == "TX":
                    buffer_length = 1370
                    port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                    self.ssl_server.interfaces.ssl.start_server()
                    server_ip = self.ssl_server.interfaces.ssl.server_ip
                    # Open ssl client socket in the DUT
                    sock = self.wifi_dut.interfaces.wifi.socket()
                    assert sock == 0, "Socket id received is wrong. expected is 0"
                    logger().info(
                        f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                    logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                    # Enable ssl option for socket opened
                    self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
                    local_port = randint(5001, 60000)
                    self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.dut_addr['device_ip'],
                                                       server_port=local_port,
                                                       timeout=15)
                    time.sleep(3)
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                   server_port=port1)
                    pkt_count = 50000
                    time.sleep(1)
                    server_socket_no = 1
                    if self.ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                        self.ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
                    result = self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
                    logger().info(f"Number of bytes sent by dut {result}")
                    bytes_sent = result
                    bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
                    logger().info(
                        f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                    logger().info("Successfully closed opened socket in the DUT")
                    self.ssl_server.interfaces.ssl.stop_server()
                    time.sleep(5)
                if self.ssl_traffic_type == "RX":
                    buffer_length = 1370
                    port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                    self.ssl_server.interfaces.ssl.start_server()
                    server_ip = self.ssl_server.interfaces.ssl.server_ip
                    time.sleep(2)
                    self.wifi_dut.interfaces.wifi.set_socket_config()
                    # Open ssl client socket in the DUT
                    time.sleep(2)
                    sock = self.wifi_dut.interfaces.wifi.async_sdk_socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                          protocol="IPPROTO_TCP")
                    assert sock == 0, "Socket id received is wrong. expected is 0"
                    logger().info(
                        f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                    logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                    # Enable ssl option for socket opened
                    self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
                    time.sleep(2)
                    self.wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(sock,
                                                                       option_name="SL_SI91X_SO_HIGH_PERFORMANCE_SOCKET",
                                                                       cert_index=128)
                    local_port = randint(5001, 60000)
                    self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.dut_addr['device_ip'],
                                                       server_port=local_port,
                                                       timeout=15)
                    time.sleep(3)
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                   server_port=port1)
                    socket_no = 1
                    pkt_count = 50000
                    duration = 60
                    self.ssl_server.interfaces.ssl.send_data(socket_no, pkt_count, msg_length=buffer_length,
                                                             duration=duration)
                    time.sleep(80)
                    bytes_sent = self.ssl_server.interfaces.ssl.data_send_stats(socket_no)
                    result = self.wifi_dut.interfaces.wifi.get_socket_rx_stats(sock, no_of_pkts="pkt_count", ttl=30)
                    logger().info(f"*** result of rx_stats in wifidut {result}")
                    bytes_received = int(result)
                    logger().info(f"bytes sent by remote peer -> {bytes_sent}")
                    logger().info(f"bytes received on socket {sock} -> {bytes_received}")
                    logger().info(f"SSL rx throughput ->  {((bytes_received * 8) / (1000 * 1000 * duration))} Mbps")
                    time.sleep(2)
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                    logger().info("Successfully closed opened socket in the DUT")
                    self.ssl_server.interfaces.ssl.stop_server()
                    time.sleep(5)

            time.sleep(2)
            if self.test_case_no == 34509:
                logger().info("This is rejoin")
            else:
                self.wifi_dut.interfaces.wifi.leave()
                time.sleep(2)
                self.wifi_sniffer.interfaces.capture.stop_capture()
                logger().info("Stop Sniffer finally")
                time.sleep(2)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2Enterprise',
                                               "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
def test_wifi_sdk_2_4_tcp_rx_wpa2_ent_C34513(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                             wifi_client, sniffer_filter, sl_collections, net_perf_client, protocol,
                                             radius_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    test_name = request.node.name
    '''Verifying connection and TCP RX traffic with WPA3 configured Access Point'''
    wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                    net_perf_client=net_perf_client, protocol=protocol, data_transfer=True,
                                    traffic_type="RX", wifi_client=wifi_client, test_case_no=34513,
                                    sniffer_filter=sniffer_filter, iteration_count=iter_count, eap_type='tls'
                                    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2Enterprise',
                                               "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
def test_wifi_sdk_2_4_udp_rx_wpa2_ent_C34515(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                             wifi_client, sniffer_filter, sl_collections, net_perf_client, protocol,
                                             radius_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    test_name = request.node.name
    '''Verifying connection and UDP RX traffic with WPA3 configured Access Point'''
    wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                    net_perf_client=net_perf_client, protocol=protocol, data_transfer=True,
                                    traffic_type="RX", sniffer_filter=sniffer_filter, wifi_client=wifi_client,
                                    test_case_no=34515, iteration_count=iter_count, eap_type='tls'
                                    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2Enterprise',
                                               "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
def test_wifi_sdk_2_4_tcp_tx_wpa2_ent_C34512(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                             wifi_client, sniffer_filter, sl_collections, net_perf_client, protocol,
                                             radius_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    test_name = request.node.name
    '''Verifying connection and TCP TX traffic with WPA3 configured Access Point'''
    wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                    net_perf_client=net_perf_client, protocol=protocol, data_transfer=True,
                                    traffic_type="TX", sniffer_filter=sniffer_filter, wifi_client=wifi_client,
                                    test_case_no=34512, iteration_count=iter_count, eap_type='tls'
                                    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2Enterprise',
                                               "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
        # "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_2_4_udp_tx_wpa2_ent_C34514(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                             wifi_client, sniffer_filter, sl_collections, net_perf_client, protocol,
                                             radius_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    test_name = request.node.name
    '''Verifying connection and UDP TX traffic with WPA3 configured Access Point'''
    wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                    net_perf_client=net_perf_client, protocol=protocol, data_transfer=True,
                                    traffic_type="TX", sniffer_filter=sniffer_filter, wifi_client=wifi_client,
                                    test_case_no=34514, iteration_count=iter_count, eap_type='tls'
                                    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2Enterprise',
                                               "passphrase": '12345678'})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.TLS_V2,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_2_4_ssl_tx_wpa2_ent_C344512(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                              wifi_client, sniffer_filter, sl_collections, radius_server, ssl_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    test_name = request.node.name
    '''Verifying connection and TCP TX traffic with WPA3 configured Access Point'''
    wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                    ssl_data_transfer=True, ssl_traffic_type="TX", sniffer_filter=sniffer_filter,
                                    wifi_client=wifi_client, iteration_count=iter_count, eap_type='tls',
                                    ssl_server=ssl_server
                                    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2Enterprise',
                                               "passphrase": '12345678'})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_2_4_ssl_rx_wpa2_ent_C344512(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                              wifi_client, sniffer_filter, sl_collections, radius_server, ssl_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    test_name = request.node.name
    '''Verifying connection and TCP TX traffic with WPA3 configured Access Point'''
    wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                    ssl_data_transfer=True, ssl_traffic_type="RX", sniffer_filter=sniffer_filter,
                                    wifi_client=wifi_client, iteration_count=iter_count, eap_type='tls',
                                    ssl_server=ssl_server
                                    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)