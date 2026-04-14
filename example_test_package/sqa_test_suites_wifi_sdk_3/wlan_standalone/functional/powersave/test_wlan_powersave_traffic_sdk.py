import pytest
import time
import random
import string
from random import randint
import re
import concurrent.futures
from datetime import datetime
from utf.interfaces.shell.ssh_shell import SSHShell
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xOperatingMode,
    DeviceConstants,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xBTFeatureBitMap,
    Si91xRegionCode
)
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from random import randint
from utf.utils.thread_base import ThreadBase

from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from threading import Thread

"""This function runs below test steps for DUT
    Step1: 1. Configuration of DUT in 2G mode
    Step2 : Do Scan the AP
    Step3: Connect to the AP
    Step4 :Initiate the different powersave modes and check the connectivity 
    Step7 : Issue init,scan and connect to the AP

    setup requirement:
        1. DUT(917-SDK)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: CG team
"""


def logger():
    return get_logger(__name__)


def transmit_stats(fixture, enable=1, power=127, rate=139,
                   length=100, mode=0, channel=1, aggr_enable=0,
                   enable_11ax=0):
    fixture.interfaces.wifi.set_antenna(interface="client", antenna=4)
    logger().info(f"Antenna Command Frame Success")
    logger().info(
        f"Transmit test start with params enable={enable}, power={power}, rate={rate}, length={length}, mode={mode}, "
        f"channel={channel}, aggr_enable={aggr_enable}, enable_11ax={enable_11ax}")
    fixture.interfaces.wifi.sl_si91x_transmit_test_start(
        enable=enable,
        power=power,
        rate=rate,
        length=length,
        mode=mode,
        channel=channel,
        aggr_enable=aggr_enable,
        enable_11ax=enable_11ax,
    )
    logger().info(f"Transmit test start Success")


def start_statistic_report(fixture, channel=1, max_stats_count=50, async_timeout=100):
    logger().info(f"\r\nReceive Statistics...\r\n")
    fixture.interfaces.wifi.start_statistic_report(interface="client", channel=channel, max_stats_count=max_stats_count,
                                                   async_timeout=async_timeout)


class TCPDataTransfer(ThreadBase):
    def __init__(self, wifi_dut, remote_socket, device_ip=None, data="Thisisfromtcpclient"):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.remote_socket = remote_socket
        # self.utf_constants = utf_constants
        self.dut_ip = device_ip
        self.data = data

    def run(self):
        logger().info("Starting TCP server socket remotely")
        local_port = randint(6000, 6100)
        # self.remote_socket.interfaces.socket.interface = "wlan0"
        logger().info("Starting TCP Server socket at remote device")
        self.remote_socket.interfaces.socket.start_server(port=local_port)
        server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
        time.sleep(5)
        server_port = self.remote_socket.interfaces.socket.server_port

        logger().info(f"DUT opens tcp client socket")
        tcp_socket_id = self.wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        bind_response = self.wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id, device_ip=self.dut_ip,
                                                           server_port=server_port,
                                                           timeout=5)
        logger().info(f"Bind socket successfully: {bind_response}")

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=server_ip,
                                                               server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        for packets in range(10):
            logger().info("DUT Sending Data packets")
            bytes_sent = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data=self.data,
                                                                     timeout=30)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")


class UDPDataTransfer(ThreadBase):
    def __init__(self, wifi_dut, remote_socket, device_ip):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.remote_socket = remote_socket
        self.device_ip = device_ip

    def run(self):
        self.data = "Data sent from DUT"
        local_port = randint(5010, 6000)
        logger().info("Starting UDP server socket at remote device")
        # self.remote_socket.interfaces.socket.interface = "wlan0"
        self.remote_socket.interfaces.socket.start_server(socket_type=1)  # 0-TCP, 1-UDP
        server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
        logger().info(f"Server_ip is {server_ip}")
        server_port = self.remote_socket.interfaces.socket.server_port
        logger().info(f"Server port is {server_port}")
        logger().info(f"DUT opens tcp client socket")
        udp_socket_id = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_DGRAM",
                                                             protocol="IPPROTO_UDP", timeout=60)
        logger().info(f"Socket open successfully : {udp_socket_id}")
        logger().info("Initiating socket bind from DUT")
        self.wifi_dut.interfaces.wifi.bind(udp_socket_id, device_ip=self.device_ip, server_port=local_port)
        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(udp_socket_id, server_ip=server_ip,
                                                               server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        time.sleep(3)
        for packets in range(20):
            logger().info("DUT Sending Data packets")
            bytes_sent = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=udp_socket_id, data=self.data,
                                                                     timeout=30)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
            logger().info("Setting UDP socket receive timeout in remote server")
            self.remote_socket.interfaces.socket.set_recv_timeout(use_client_socket=True, socket_type=1)
            recv_data, address = self.remote_socket.interfaces.socket.recv_data_udp(data_size=len(self.data))
            logger().info(f"data received : {recv_data}")
            packets = packets + 1
            logger().info(f"total packets received at the remote socket: {packets}")

        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=udp_socket_id)
        self.remote_socket.interfaces.socket.stop()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19500')
def test_power_mode_switching_before_assoc_C19500(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                  sniffer_filter, sl_collections):
    """
    Power Save Mode switching before association
    """
    try:
        capture_filename = "test_power_mode_switching_before_assoc_c19500"
        channel = wifi_access_point.interfaces.wifi.channel
        logger().info(f"Configuring the sniffer with channel {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("Starting capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        time.sleep(5)
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            time.sleep(5)
            logger().info(f"Iterating for {iter_count}: Current iteration is {i}")
            logger().info("Enabling power Save")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

            time.sleep(5)
            logger().info("Disabling power save ")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            logger().info("enable the scan in dut on channel 0...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "Scan Failed"
            logger().info(scan_results)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT mac address is {sa_addr}")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sa_addr, filter_name="probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request broadcast packet'
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19501')
def test_powersave_disable_functionality_powersave1_C19501(wifi_access_point, wifi_dut, wifi_sniffer, rs_helper,
                                                           sniffer_filter, sl_collections):
    """
    Power save disable functionality when module is in power save
    """
    try:

        validation = True
        capture_filename = "test_C19501_max_psp_enabled"
        channel = wifi_access_point.interfaces.wifi.channel

        logger().info(f"Configuring the sniffer with channel {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("Starting capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                                                     associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        logger().info(f"DUT MAC: {dut_mac_address}")
        time.sleep(30)
        logger().info(f"***** Enabling Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")

        ping_status = sl_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=300)
        assert ping_status, "DUT is not responding to ping request after powersave"
        logger().info("ping to DUT is successful....")
        time.sleep(30)

        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                        da_addr=ap_bssid,
                                                                                        filter_name='power_mgmt_bit')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Qos Null with PM1'

        capture_filename2 = "test_C19501_max_psp_disabled"
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("Starting capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename2}.pcap")
        time.sleep(5)

        logger().info("Disabling wlan power save")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")

        time.sleep(60)
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        logger().info("CHECKING MAX PSP DISABLED - SO SHOULD NOT GET NUL PACKETS")
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                        da_addr=ap_bssid,
                                                                                        filter_name='power_mgmt_bit_disable')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], "Unable to find Qos Null with PM 0"

        wifi_dut.interfaces.wifi.leave()

        logger().info(f"CASE 2: CHECKING CASE2 ENHANCED MAX PSP")
        capture_filename = "test_C19501_enhanced_max_psp_enabled"

        channel = wifi_access_point.interfaces.wifi.channel
        logger().info(f"Configuring the sniffer with channel {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("Starting capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        logger().info("Configuring ENHANCED MAX PSP")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                                                     associated=False)

        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        time.sleep(30)

        logger().info(f"***** Enabling Enhanced Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")

        ping_status = sl_collections.ping_with_custom_size(device_ip, ping_counts=30, byte_size=300)
        assert ping_status, "DUT is not responding to ping request after powersave"
        logger().info("ping to DUT is successful....")
        logger().info("Stopping sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                        da_addr=ap_bssid,
                                                                                        filter_name='power_mgmt_bit')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Qos Null with PM1'

        capture_filename2 = "test_C19501_enhance_max_psp_disabled"
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("Starting capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename2}.pcap")
        time.sleep(5)

        logger().info("Disabling power save ")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")
        time.sleep(60)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("CHECKING ENHANCDED MAX PSP DISABLED - SO SHOULD NOT GET NUL PACKETS")

        validation = True
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                        da_addr=ap_bssid,
                                                                                        filter_name='power_mgmt_bit_disable')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], "Unable to find Qos Null with PM 0"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["multicast_leave", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19507')
def test_send_multicast_broadcast_data_sdk_C19507(multicast_client, net_perf_client, protocol,
                                                  wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, utf_constants,
                                                  sl_collections, sniffer_filter):
    """
    Sending of broadcast and multicast data with power save enabled
    """
    try:
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            capture_filename = f"test_Send_Multicast_data_C19507_sdk_iteration_{i}"
            channel = wifi_access_point.interfaces.wifi.channel

            logger().info(f"Configuring the sniffer with channel {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            logger().info("Starting capture")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP BSSID = {ap_bssid}')
            wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                     beacon_missed_count=40, first_time_retry_enable=0)

            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True, ping_count=10,
                                                         associated=False, retry_count=3)
            device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

            logger().info(f"***** Start get IP address ******")
            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"***** host ip is {host_ip}")
            logger().info(f"***** Device ip is {device_ip}")

            timeout = 60

            logger().info(f"***** Running broadcast data")
            ip_str = device_ip.split(".")
            ip_str[3] = "255"
            broadcast_ip = ".".join(ip_str)
            logger().info(f"Broadcast ip is {broadcast_ip}")

            logger().info(f"SENDING MULTICAST DATA")
            (ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length,
             no_of_pkts) = multicast_client.interfaces.multicast.multicast_params()

            logger().info(f"DUT joining to the multicast group {multicast_ip}")
            wifi_dut.interfaces.wifi.sl_net_join_multicast_address()

            net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=multicast_ip, time_out=timeout,
                                                            protocol=protocol, time_to_leave="32", bandwidth="60M",
                                                            host_role="C", bind_address=host_ip)
            logger().info(f"Host IP: {host_ip}, Dut IP: {device_ip}, Protocol: {protocol}")
            logger().info(f"***** starting iperf ******")
            net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** start listening  ******")
            wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                           local_port=net_perf_client.interfaces.net_perf.client_port,
                                           local_ip=multicast_ip, remote_ip=host_ip,
                                           remote_port=net_perf_client.interfaces.net_perf.client_port,
                                           size=1470, ttl=30, throughput_type=4, qos=0, async_socket=1)

            wifi_dut.interfaces.wifi.sl_net_leave_multicast_address()

            logger().info(f"SENDING BROADCAST DATA")
            sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                                       device_ip=broadcast_ip, host_ip=host_ip, timeout=60, traffic_type="TX")

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Initiating disconnect from DUT")
            # Wlan Disconnect
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)

            logger().info("validate NULL data frame with PM bit set to '1'")
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                            da_addr=ap_bssid,
                                                                                            filter_name='power_mgmt_bit')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Unable to find power management bit in QOS null frames in sniffer capture'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19509')
def test_powersave_mode_2_enterprise_sdk_C19509(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                radius_server, sl_collections, request, utf_constants,
                                                net_perf_client, wifi_client, protocol):
    """
    Power mode 2 data transfer in Enterprise security mode
    """
    try:
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            testcase = "test_powersave_mode_2_Enterprise_C19509"
            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP bssid {ap_bssid}")

            dut_addr = sl_collections.join_to_eap_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                                          eap_type="tls", ping_after_power_save=True, power_save=False)
            device_ip = dut_addr['device_ip']
            dut_mac_address = dut_addr['dut_mac_address']
            logger().info(f"device_ip, device_mac : {dut_addr['device_ip']}, {dut_addr['dut_mac_address']}")

            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{host_ip}")

            logger().info("Enabling power save Enhanced max psp")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            time.sleep(10)

            # Enables the bt power save in DUT
            logger().info("Setting DUT in bt power save...")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            time.sleep(30)

            logger().info(f"Running UDP-Rx Traffic")
            sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=IperfConstants.UDP,
                                       device_ip=device_ip, host_ip=host_ip, timeout=60, traffic_type="RX")
            time.sleep(60)

            logger().info(f"Running TCP -Rx traffic")
            sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                                       device_ip=device_ip, host_ip=host_ip, timeout=30, traffic_type="RX")
            time.sleep(30)

            logger().info("Initiating disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("validate NULL data frame with PM bit set to '1'")
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                            da_addr=ap_bssid,
                                                                                            filter_name='power_mgmt_bit')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Unable to find power management bit in QOS null frames in sniffer capture'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("test_run_time", [1800])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19485')
def test_connect_and_disconnect_when_module_is_in_power_save_mode_C19485(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                         test_run_time, sl_collections, sniffer_filter,
                                                                         utf_constants):
    """ Test agent ticket is raised for this test case https://jira.silabs.com/browse/WIFI_BT_UTFHELP-4601"""
    logger().info(f"The test case will be executed for {test_run_time} seconds")
    sw = Stopwatch()
    iteration = 0
    error_count = 0
    expected_error_count = 10
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    while sw.elapsed_sec < test_run_time:
        try:
            iteration = iteration + 1
            logger().info(f"################Iteration count -> {iteration}")
            validation = True

            capture_filename = "test_connect_disconnect_power_save_c19485"
            channel = wifi_access_point.interfaces.wifi.channel
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

            time.sleep(30)
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True, ping_count=10,
                                                         associated=False, retry_count=3)
            device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            time.sleep(60)

            logger().info(f'DUT ip {device_ip}')
            logger().info("pinging to dut.....")
            ping_status = sl_collections.ping_with_custom_size(device_ip, ping_counts=30, byte_size=300)
            assert ping_status, "DUT is not responding to ping request after powersave"
            logger().info("ping to DUT is successful....")

            # Add disconnect.leave api
            logger().info(f"Disconnect using api")
            wifi_dut.interfaces.wifi.leave()

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("validate NULL data frame with PM bit set to '1'")

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                            da_addr=ap_bssid,
                                                                                            filter_name='power_mgmt_bit')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Unable to find power management bit in QOS null frames in sniffer capture'

            wifi_dut.interfaces.wifi.inited = False
            wifi_dut.interfaces.wifi.associated = False
            logger().info(f"Initialising De init")
            wifi_dut.interfaces.wifi.deinit()
            logger().info(f"Initialising init")
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            wifi_dut.interfaces.wifi.init(load_certificate=False)
            wifi_dut.interfaces.wifi.initialize_thread()
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            logger().info(f"Initialising init completed")

        except:
            error_count = error_count + 1
            logger().info(
                f"### Failure Count {error_count}: Failed in iteration -> {iteration} at {sw.elapsed_sec} seconds")
            continue
        finally:
            if error_count > expected_error_count:
                logger().info(f"*** Error count is {error_count}. Here error count is more than expected ***")
                logger().error(
                    f"\n\n********** Observed error count '{error_count}' times which is more than expected"
                    f" error count '{expected_error_count}', Hence marking the testcase as fail **********")
            logger().info(f"wifi reset is running....")
            wifi_dut.interfaces.wifi.reset()
            logger().info(f"Initialising init")
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            wifi_dut.interfaces.wifi.init(load_certificate=False)
            wifi_dut.interfaces.wifi.initialize_thread()
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            assert error_count <= expected_error_count, (f"Error count is more than  '{expected_error_count}' times in "
                                                         f" of test run time: {test_run_time} Hence failing the test "
                                                         f"case")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19494')
def test_TCP_UDP_bidi_in_powersave_mode2_ulp_sdk_C19494(wifi_sniffer, remote_socket, wifi_dut,
                                                        wifi_access_point, utf_constants,
                                                        sl_collections, sniffer_filter, net_perf_client, wifi_client):
    iter_count = utf_constants.get("iter_count")
    try:
        for i in range(iter_count):
            logger().info(f"Iteration count {i}")
            Validation = True
            capture_filename = "test_C19494"
            channel = wifi_access_point.interfaces.wifi.channel

            logger().info(f"Configuring the sniffer with channel {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            logger().info("Starting capture")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP BSSID = {ap_bssid}')
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                                                         associated=False)
            device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            logger().info(f"DUT MAC: {dut_mac_address}")
            time.sleep(30)
            logger().info(f"***** Enabling Max PSP in DUT ******")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            logger().info(f'DUT ip {device_ip}')
            logger().info("pinging to dut.....")

            ping_status = sl_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=300)
            assert ping_status, "DUT is not responding to ping request after powersave"
            logger().info("ping to DUT is successful....")
            time.sleep(30)

            logger().info("Starting TCP and UDP Data")
            t1 = TCPDataTransfer(wifi_dut, remote_socket, device_ip)
            t1.start()
            t1.wait_for_exit()

            t2 = UDPDataTransfer(wifi_dut, remote_socket, device_ip)
            t2.start()
            t2.wait_for_exit()

            logger().info("Initiating disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("validate NULL data frame with PM bit set to '1'")
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                            da_addr=ap_bssid,
                                                                                            filter_name='power_mgmt_bit')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Unable to find power management bit in QOS null frames in sniffer capture'

            # logger().info("Resetting DUT")
            # wifi_dut.interfaces.wifi.reset()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19508')
def test_powersave_functionality_after_rejoin_sdk_C19508(switch, wifi_sniffer, wifi_dut, wifi_access_point,
                                                         utf_constants, sniffer_filter,
                                                         sl_collections):
    # def test_powersave_functionality_after_rejoin_sdk_C19508(wifi_sniffer, wifi_dut, wifi_access_point,utf_constants,sl_collections):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    try:
        for i in range(iter_count):
            logger().info(f"Iteration {i}")
            validation = True
            capture_filename = "test_powersave_functionality_after_rejoin_C19508"
            channel = wifi_access_point.interfaces.wifi.channel
            logger().info(f"Configuring the sniffer with channel {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            logger().info("Starting capture")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP BSSID = {ap_bssid}')
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                                                         associated=False)
            device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            logger().info(f"DUT MAC: {dut_mac_address}")
            time.sleep(30)
            logger().info(f"***** Enabling Max PSP in DUT ******")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            logger().info(f'DUT ip {device_ip}')
            logger().info("pinging to dut.....")

            ping_status = sl_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=300)
            assert ping_status, "DUT is not responding to ping request after powersave"
            logger().info("ping to DUT is successful....")
            time.sleep(30)

            validation = True
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=dut_mac_address,
                da_addr=ap_bssid,
                filter_name='power_mgmt_bit')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "Unable to find Qos Null with PM 1"

            channel = wifi_access_point.interfaces.wifi.channel
            capture_filename_2 = "test_power_save_functionality_after_rejoin_C19508_after_turn_off"
            logger().info(f"Configuring the sniffer with channel {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            logger().info("Starting capture")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename_2}.pcap")
            time.sleep(5)

            logger().info("***** Turn off Access Point *****")
            switch.interfaces.pdu_switch.turn_off(delay=20)
            # wifi_access_point.interfaces.wifi.stop_ap()
            # time.sleep(60)

            logger().info("***** Turn on Access Point *****")
            switch.interfaces.pdu_switch.turn_on(delay=100)

            logger().info("Pinging to DUT to check rejoin process is completed or not")
            status = sl_collections.ping(device_ip, 30, 5)
            assert status, "Pinging to DUT is failed, DUT not rejoined to AP"

            time.sleep(10)
            wifi_sniffer.interfaces.capture.stop_capture()

            validation = True
            logger().info(f"Checking whether DUT is again went to power save for data collection")
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                            da_addr=ap_bssid,
                                                                                            filter_name='power_mgmt_bit')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "Unable to find Qos Null with PM 1"

            logger().info("Initiating disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        # logger().info("\n\nEnabling Wireless in AP")
        # wifi_access_point.interfaces.wifi.start_ap()
        # time.sleep(60)


# Need two evk harness
@pytest.mark.skip("Not announced yet")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 0, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.PERMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    sapi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                          "ble": {"count": 0, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.PERMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": Si91xRegionCode.Worldwide,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C34780')
def test_wifi_sdk_sta_check_basic_per_transmit_and_receive_two_evk_c34780(wifi_dut, wifi_access_point,
                                                                          remote_wiseconnect3, sl_collections,
                                                                          wifi_sniffer, request, sniffer_filter):
    """
        Test the basic PER (Packet Error Rate) transmit and receive functionality between two EVKs (Evaluation Kits).

        This test performs the following steps:
        1. Configures the sniffer on the WiFi access point channel.
        2. Starts the sniffer capture.
        3. Executes the TX (transmit) test by running `transmit_stats` on `wifi_dut` and `start_statistic_report` on `remote_wiseconnect3`.
        4. Stops the statistic report on `remote_wiseconnect3`.
        5. Executes the RX (receive) test by running `transmit_stats` on `remote_wiseconnect3` and `start_statistic_report` on `wifi_dut`.
        6. Stops the statistic report on `wifi_dut`.
        7. Stops the sniffer capture.

        Args:
            wifi_dut: The Device Under Test (DUT) WiFi interface.
            wifi_access_point: The WiFi access point interface.
            remote_wiseconnect3: The remote WiFi interface for the second EVK.
            sl_collections: Collection of utility functions for the test.
            wifi_sniffer: The WiFi sniffer interface.
            request: The pytest request object containing test metadata.

        Raises:
            Exception: If any error occurs during the test execution.
        """
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{request.node.name}.pcap")
        logger().info(f"Starting the TX Test")
        primary_dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        secondary_dut_mac_address = remote_wiseconnect3.interfaces.wifi.get_mac_address()
        logger().info(
            f"\r\n The Primary DUT MAC address is {primary_dut_mac_address} and the secondary DUT MAC address is "
            f"{secondary_dut_mac_address} \r\n")
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Submit the functions to the executor
            executor.submit(transmit_stats, wifi_dut)
            executor.submit(start_statistic_report, remote_wiseconnect3)
        remote_wiseconnect3.interfaces.wifi.stop_statistic_report()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=primary_dut_mac_address,
            filter_name="association_request_with_malformed_packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find association request broadcast packet'

        logger().info(f"Starting the RX Test")
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Submit the functions to the executor
            executor.submit(transmit_stats, remote_wiseconnect3)
            executor.submit(start_statistic_report, wifi_dut)
        wifi_dut.interfaces.wifi.stop_statistic_report()

        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().error(f"Exception occurred: {e}")  # Log the exception
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
