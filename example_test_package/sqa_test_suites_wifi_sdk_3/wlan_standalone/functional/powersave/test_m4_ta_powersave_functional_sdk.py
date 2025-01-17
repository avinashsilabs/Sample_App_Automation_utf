import time
import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xJoinFeatureBitMap
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.logger import get_logger
import random
from random import randint
from utf.utils.iperf.iperf_utils import ping


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in Wlan & coex mode for 2.4Ghz.
        2. Initiate the Scan from DUT.
        3. Initiate the connection with third party Access Point.
        4. Run the traffic TCP/UDP TX & RX.
        5. Verify m4 and ta wake up when received the wireless packet.  

    setup requirement:
        1. DUT(SiWG917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. NUC

    Author: RaviNemali 
"""

pytestmark = [pytest.mark.firmware_app("test_480K_M4SS_320K")]


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
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
def test_m4_interrupt_ta_listen_interval_C514372(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                                 remote_socket, protocol, utf_constants, sl_collections):
    """Execute M4 Wakes up from sleep randomly,M4 will interrupt TA to wakeup(TA-Listen interval Based powersave),
    TA will send TCP Tx to TCP Server"""
    listen_interval = 1100
    try:
        logger().info("starting the sniffer")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_m4_interrupt_ta_listen_interval_C514372')
        time.sleep(2)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                         Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(5, 1)
        dut_add_dict = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                           wifi_access_point=wifi_access_point,
                                                           associated=wifi_dut.interfaces.wifi.associated,
                                                           retry_count=3, ping_after_power_save=False,
                                                           ping_count=10, power_save=False,
                                                           mode='power_save',
                                                           listen_interval=1100
                                                           )

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        wifi_dut.interfaces.wifi.enable_bt_power_save(2, 0)

        logger().info("Starting TCP server socket remotely")
        local_port = randint(6000, 6100)
        remote_socket.interfaces.socket.interface = "eth1"
        logger().info("Starting TCP Server socket at remote device")
        remote_socket.interfaces.socket.start_server(port=local_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = remote_socket.interfaces.socket.server_port

        logger().info(f"DUT opens tcp client socket")
        tcp_socket_id = wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        bind_response = wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id, device_ip=dut_add_dict['device_ip'],
                                                      server_port=server_port,
                                                      timeout=5)
        logger().info(f"Bind socket successfully: {bind_response}")

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=server_ip,
                                                          server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")

        for packets in range(5):
            logger().info("DUT Sending Data packets")
            bytes_sent = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data="tapowersaveinterrupt",
                                                                timeout=30)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
            logger().info("Setting TCP socket receive timeout in remote server")
            remote_socket.interfaces.socket.set_recv_timeout(socket_type=0)
            recv_data = remote_socket.interfaces.socket.recv_data_tcp(data_size=len("tapowersaveinterrupt"))
            logger().info(f"data received : {recv_data}")
            packets = packets + 1
            logger().info(f"total packets received at the remote socket: {packets}")
            wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=10000)

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=tcp_socket_id)
        remote_socket.interfaces.socket.stop()

    except Exception as e:
        logger().error(f"Exception occurred: {e}")
        raise e


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
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
def test_m4_interrupt_ta_DTIM_based_C514376(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                            remote_socket, protocol, utf_constants, sl_collections):
    """Execute M4 Wakes up from sleep randomly,M4 will interrupt TA to wakeup(TA-DTIM Based powersave),
    TA will send TCP Tx to TCP Server"""
    try:
        logger().info("starting the sniffer")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_m4_interrupt_ta_DTIM_based_C514376')
        time.sleep(2)

        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(5, 1)
        dut_add_dict = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                           wifi_access_point=wifi_access_point,
                                                           associated=wifi_dut.interfaces.wifi.associated,
                                                           retry_count=3, ping_after_power_save=False,
                                                           ping_count=10, power_save=False,
                                                           mode='power_save'
                                                           )

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        wifi_dut.interfaces.wifi.enable_bt_power_save(2, 0)

        logger().info("Starting TCP server socket remotely")
        local_port = randint(6000, 6100)
        remote_socket.interfaces.socket.interface = "eth1"
        logger().info("Starting TCP Server socket at remote device")
        remote_socket.interfaces.socket.start_server(port=local_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = remote_socket.interfaces.socket.server_port

        logger().info(f"DUT opens tcp client socket")
        tcp_socket_id = wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        bind_response = wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id, device_ip=dut_add_dict['device_ip'],
                                                      server_port=server_port,
                                                      timeout=5)
        logger().info(f"Bind socket success: {bind_response}")

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=server_ip,
                                                          server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")

        for packets in range(5):
            logger().info("DUT Sending Data packets")
            bytes_sent = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data="tapowersaveinterrupt",
                                                                timeout=30)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
            logger().info("Setting TCP socket receive timeout in remote server")
            remote_socket.interfaces.socket.set_recv_timeout(socket_type=0)
            recv_data = remote_socket.interfaces.socket.recv_data_tcp(data_size=len("tapowersaveinterrupt"))
            logger().info(f"data received : {recv_data}")
            packets = packets + 1
            logger().info(f"total packets received at the remote socket: {packets}")
            wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=10000)

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=tcp_socket_id)
        remote_socket.interfaces.socket.stop()

    except Exception as e:
        logger().error(f"Exception occurred: {e}")
        raise e
