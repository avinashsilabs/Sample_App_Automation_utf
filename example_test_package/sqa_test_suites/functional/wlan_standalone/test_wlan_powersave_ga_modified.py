import pytest
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                                            RS9116CustomFeatureBitMap,
                                            RS9116ConfigFeatureBitMap,
                                            RS9116TCPIPFeatureBitMap,
                                            RS9116ExtCustomFeatureBitMap,
                                            RS9116ExtTCPIPFeatureBitMap,
                                            RS9116SecurityMode,
                                            RS9116OperatingMode,
                                            RS9116PowerSaveProcedureTypes,
                                            DeviceConstants,
                                            SocketType,
                                            SocketOptions,
                                            )
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping
from utf.utils.stopwatch import Stopwatch
import time
from random import randint
from threading import Thread
import threading
import string
import random
from utf.utils.time_measurer import TimeMeasurer

"""This function runs below test steps for DUT-RS9116
    Step1: 1. Configuration of DUT in 2G mode
    Step2 : Do Scan the AP
    Step3: Connect to the AP
    Step4 :Initiate the different powersave modes and check the connectivity 
    Step7 : Issue init,scan and connect to the AP
    Need to use separate .hex files for lp and ulp msb_based and gpio based cases.

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)

    Author: Vinod.G 
"""


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


class tx_rx:
    def __init__(self):
        self.thread_lock = threading.Lock()
        self.sent_data = 0
        self.rcv_data = 0

    def receive_data_socket(self, remote_socket, logger, no_of_pkts, data_size, proto_type=0):
        fail_count = 0
        for count in range(0, no_of_pkts):
            if proto_type == 0:
                data = remote_socket.interfaces.socket.recv_data_tcp(data_size, timeout=20)
            else:
                data, address = remote_socket.interfaces.socket.recv_data_udp(data_size)
            if not isinstance(data, str):
                fail_count = fail_count + 1
                if fail_count == 5:
                    break
                else:
                    continue
            self.rcv_data = self.rcv_data + len(data)
        logger.info(f"Total bytes received on socket opened remotely -> {self.rcv_data}")

    def send_data(self, remote_socket, logger, data_size, test_run_time=300, proto_type=0, server_ip=None,
                  server_port=None):
        sw = Stopwatch()
        tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=data_size))
        while sw.elapsed_sec < test_run_time:
            if proto_type == 0:
                data = remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server_socket=True)
            else:
                data = remote_socket.interfaces.socket.send_data_udp(tx_buffer, server_ip, server_port)
                time.sleep(0.1)
            self.sent_data = self.sent_data + data
        logger.info(f"Total bytes sent on socket opened remotely -> {self.sent_data}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("test_run_time", [1800])
def test_connect_and_disconnect_when_module_is_in_power_save_mode_C19485(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                         test_run_time):
    logger().info(f"The test case will be executed for {test_run_time} seconds")
    sw = Stopwatch()
    iteration = 0
    while sw.elapsed_sec < test_run_time:
        iteration = iteration + 1
        logger.info(f"#####################################################Iteration count -> {iteration}")
        validation = True
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_connect_and_disconnect_when_module_is_in_power_save_mode_C19485')
        # Connect to the AP
        result = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        assert result is not None, "Could not connect to the AP"
        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')
        logger().info(f"This API Enables the DHCP in DUT")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"*****Enable Power save in DUT******")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.MaxPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.MaxPowerSave)

        ping_count = 10
        logger().info("pinging to dut ip")
        status = ping(device_ip, ping_count)
        assert status == 1, "ping to dut is failed after power save..."
        logger().info("ping to dut is successful after power save...")
        time.sleep(30)
        # Add disconnect.leave api
        wifi_dut.interfaces.wifi.leave()
        logger().info("validate NULL data frame with PM bit set to '1'")
        logger().info("Verifying powersave mode 2 bit")
        packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {bssid}))'

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
        wifi_dut.interfaces.wifi.inited = False
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.wireless_deinit()
        wifi_dut.interfaces.wifi.init(reset_type="rs911x")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode1_C19486(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut,
                                                            wifi_client,
                                                            protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_TCP_UDP_Rx_data_transfer_in_powersave_mode1_C19486')
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"Fetched the device ip address,{device_ip}")
    logger().info(f"*****Enable  Max Power save in DUT******")
    # Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1,
                                                 RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode1, RS9116PowerSaveProcedureTypes.MaxPowerSave
        )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=300)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

        tp = net_perf_client.interfaces.net_perf.process_output()
        if tp is not None:
            print_dict("## ", tp)
        logger().info(f"Iperf data transfer completed successfully")

    logger().info("validate NULL data frame with PM bit set to '1'")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit set to 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.firmware_app("test_wlan_powersave_mode2_lp")
@pytest.mark.skip()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
def test_TCP_UDP_Tx_data_transfer_in_powersave_mode2_lp_C19488(firmware_loader, net_perf_client, wifi_sniffer,
                                                               wifi_access_point, wifi_dut,
                                                               wifi_client,
                                                               protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file="test_TCP_UDP_Tx_data_transfer_in_powersave_mode2_lp_C19488")
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    time.sleep(2)
    # Connect to the AP
    logger().info("Connecting to the Access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    # preparing wifi_client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    logger().info(f"*****Enable  Max Power save in DUT******")
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.MaxPowerSave
        )
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping to dut is failed..."
    logger().info("ping to dut is successful after power save...")
    # starting iperf

    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=300)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
        )
    tp = net_perf_client.interfaces.net_perf.process_output()
    if tp is not None:
        print_dict("## ", tp)
    logger().info(f"Iperf data transfer completed successfully")

    logger().info("validate NULL data frame with PM bit set to 1")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.firmware_app("test_wlan_powersave_mode2_lp")
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.skip()
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode2_lp_C19489(firmware_loader, net_perf_client, wifi_sniffer,
                                                               wifi_access_point, wifi_dut,
                                                               wifi_client,
                                                               protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_TCP_UDP_Rx_data_transfer_in_powersave_mode2_lp_C19489')
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"Fetched the device ip address, {device_ip}")

    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.MaxPowerSave
        )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping to dut is failed..."
    logger().info("ping to dut is successful after power save...")
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=300)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

        tp = net_perf_client.interfaces.net_perf.process_output(result)
        if tp is not None:
            print_dict("## ", tp)
        logger().info(f"Iperf data transfer completed successfully")

        # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.firmware_app("test_wlan_powersave_mode3_lp")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
def test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_lp_C19491(firmware_loader, net_perf_client, wifi_sniffer,
                                                               wifi_access_point, wifi_dut,
                                                               wifi_client,
                                                               protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_lp_C19491')
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("Connecting to the Access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    # preparing wifi_client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.MaxPowerSave
        )
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping dut failed..."
    logger().info("ping to dut is successful...")
    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=300)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
        )
    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    if tp is not None:
        print_dict("## ", tp)
    logger().info("data transfer is successful")

    logger().info("validate NULL data frame with PM bit set to 1")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.firmware_app("test_wlan_powersave_mode3_lp")
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_lp_C19492(firmware_loader, net_perf_client, wifi_sniffer,
                                                               wifi_access_point, wifi_dut,
                                                               wifi_client,
                                                               protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_lp_C19492')
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"Fetched the device ip address, {device_ip}")

    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.MaxPowerSave
        )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping to dut is failed..."
    logger().info("ping to dut is successful after power save...")
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=300)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

        tp = net_perf_client.interfaces.net_perf.process_output(result)
        if tp is not None:
            print_dict("## ", tp)
        logger().info(f"Iperf data transfer completed successfully")

        # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
def test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_C19495(firmware_loader, net_perf_client, wifi_sniffer,
                                                            wifi_access_point, wifi_dut,
                                                            wifi_client,
                                                            protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_C19495')
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    time.sleep(2)
    # Connect to the AP
    logger().info("Connecting to the Access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    # preparing wifi_client
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.MaxPowerSave
        )
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping to dut failed..."
    logger().info("ping to dut is successful after power save...")
    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol, time_out=300)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
        )
    logger().info("validate NULL data frame with PM bit set to 1")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_C19496(firmware_loader, net_perf_client, wifi_sniffer,
                                                            wifi_access_point, wifi_dut,
                                                            wifi_client,
                                                            protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_C19496')
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"Fetched the device ip address, {device_ip}")
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.MaxPowerSave
        )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    ping_count = 10
    logger().info("pinging to dut ip")
    status = ping(device_ip, ping_count)
    assert status == 1, "ping to dut failed..."
    logger().info("ping to dut is successful after power save...")
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=300)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

        tp = net_perf_client.interfaces.net_perf.process_output(result)
        if tp is not None:
            print_dict("## ", tp)
        logger().info(f"Iperf data transfer completed successfully")

        logger().info("validate NULL data frame with PM bit set to '1'")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_powersave_disable_functionality_powersave1_C19501(wifi_access_point, wifi_dut, wifi_sniffer):
    validation = True
    capture_file1 = "test_powersave_disable_functionality_powersave1_C19501" + "powersave_enable"
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_file1)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # Get IP over DHCP
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Powersave2 in  DUT******")
    # Initiating power save2
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1,
                                        RS9116PowerSaveProcedureTypes.MaxPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode1,
                                           RS9116PowerSaveProcedureTypes.MaxPowerSave)
    logger().info(f"Wait for 30 seconds")
    time.sleep(30)
    logger().info("validate NULL data frame with PM bit set to '1'")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    logger().info(
        "DUT sent null data pkt with power save bit enabled to 1 when power save is enabled which is expected")
    capture_file2 = "test_powersave_disable_functionality_powersave1_C19501" + "powersave_disable"
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_file2)

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled,
                                        0)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled,
                                           0)
    wifi_dut.interfaces.wifi.leave()
    logger().info("validate NULL data frame with PM bit set to '0'")
    packet_filter2 = f' (wlan.fc.pwrmgt == 0) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 0')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 0'
    logger().info("DUT sent null data pkt with power save bit enabled to 0 when power save is disabled which is "
                  "expected")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_powersave_disable_functionality_powersave2_C19501(wifi_access_point, wifi_dut, wifi_sniffer):
    validation = True
    capture_file1 = "test_powersave_disable_functionality_case2_C19501" + "powersave_enable"
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_file1)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # Get IP over DHCP
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Powersave2 in  DUT******")
    # Initiating power save2
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.MaxPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.MaxPowerSave)
    logger().info(f"Wait for 30 seconds")
    time.sleep(30)
    logger().info("validate NULL data frame with PM bit set to '1'")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    logger().info(
        "DUT sent null data pkt with power save bit enabled to 1 when power save is enabled which is expected")
    capture_file2 = "test_powersave_disable_functionality_case2_C19501" + "powersave_disable"
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_file2)

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled,
                                        0)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled,
                                           0)
    wifi_dut.interfaces.wifi.leave()
    logger().info("validate NULL data frame with PM bit set to '0'")
    packet_filter2 = f' (wlan.fc.pwrmgt == 0) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 0')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 0'
    logger().info("DUT sent null data pkt with power save bit enabled to 0 when power save is disabled which is "
                  "expected")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_powersave_disable_functionality_powersave3_C19501(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer):
    validation = True
    capture_file1 = "test_powersave_disable_functionality_case3_C19501" + "powersave_enable"
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_file1)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # Get IP over DHCP
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Powersave2 in  DUT******")
    # Initiating power save2
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.MaxPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.MaxPowerSave)
    logger().info(f"Wait for 30 seconds")
    time.sleep(30)
    logger().info("validate NULL data frame with PM bit set to '1'")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    logger().info(
        "DUT sent null data pkt with power save bit enabled to 1 when power save is enabled which is expected")
    capture_file2 = "test_powersave_disable_functionality_case3_C19501" + "powersave_disable"
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_file2)

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled,
                                        0)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled,
                                           0)
    wifi_dut.interfaces.wifi.leave()
    logger().info("validate NULL data frame with PM bit set to '0'")
    packet_filter2 = f' (wlan.fc.pwrmgt == 0) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 0')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 0'
    logger().info("DUT sent null data pkt with power save bit enabled to 0 when power save is disabled which is "
                  "expected")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.TCP_IP_BI_DIR_ACK_UPDATE,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.parametrize("protocol", ["TCP", "UDP"])
@pytest.mark.parametrize("number_of_pkts", [1000])
@pytest.mark.parametrize("test_run_time", [200])
def test_TCP_UDP_bidirectional_in_powersave_mode1_TC19487(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point,
                                                          logger, number_of_pkts, protocol, test_run_time):
    data_size = 1460
    remote_socket.interfaces.socket.time_limit = 1800
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_TCP_UDP_bidirectional_in_powersave_mode1_TC19487')
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger.info(f"Fetched the device ip address,{device_ip}")
    logger.info(f"*****Enable  Max Power save in DUT******")
    # Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1,
                                                 RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode1, RS9116PowerSaveProcedureTypes.MaxPowerSave
        )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {bssid}')
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    if protocol == "TCP":
        logger.info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server()
        # DUT opens tcp client socket
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"socket id received is {sock} which is expected")
        logger.info(
            f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # tcp socket opened in DUT connects to the tcp server
        wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    else:
        logger.info("Starting udp socket remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(socket_type=1)
        # Open UDP socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, "socket id received is not matched. Expected is 0"
        logger.info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    tx_rx_obj = tx_rx()
    if protocol == "TCP":
        th_start = Thread(target=tx_rx_obj.receive_data_socket,
                          args=(remote_socket, logger, number_of_pkts, data_size, 0), )
        th_start1 = Thread(target=tx_rx_obj.send_data, args=(remote_socket, logger, data_size, test_run_time, 0), )
    else:
        th_start = Thread(target=tx_rx_obj.receive_data_socket,
                          args=(remote_socket, logger, number_of_pkts, data_size, 1), )
        th_start1 = Thread(target=tx_rx_obj.send_data,
                           args=(remote_socket, logger, data_size, test_run_time, 1, device_ip, local_port), )

    th_start.start()
    th_start1.start()
    time.sleep(1)
    with TimeMeasurer() as t:
        if protocol == "TCP":
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts)
        else:
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                                 server_ip="192.168.50.81", server_port=5001)
    tx_time = t.duration
    logger.info(f"Number of bytes sent by dut {bytes_sent}")
    delta_time = 5
    time.sleep(test_run_time - tx_time + delta_time)
    th_start.join(5)
    th_start1.join(5)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
    bytes_received = int(result.split(b":")[1])
    logger.info(f"bytes received on socket {sock} -> {bytes_received}")
    assert bytes_sent == tx_rx_obj.rcv_data, "Number of bytes sent by DUT and received on remote socket are not " \
                                             "matched "
    packet_loss = (((tx_rx_obj.sent_data - bytes_received) / tx_rx_obj.sent_data) * 100)
    logger.info(f"Packet loss {packet_loss}")
    assert packet_loss < 20, "Packet loss is not in tolerance level while DUT receiving the data"

    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)
    logger.info("Successfully closed opened socket in the DUT")
    logger.info("validate NULL data frame with PM bit set to '1'")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit set to 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.TCP_IP_BI_DIR_ACK_UPDATE,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.skip()
@pytest.mark.firmware_app("test_wlan_powersave_mode2_lp")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.parametrize("protocol", ["TCP", "UDP"])
@pytest.mark.parametrize("number_of_pkts", [1000])
@pytest.mark.parametrize("test_run_time", [200])
def test_TCP_UDP_bidirectional_in_powersave_mode2_lp_TC19490(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point,
                                                             logger, number_of_pkts, protocol, test_run_time):
    data_size = 1460
    remote_socket.interfaces.socket.time_limit = 1800
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_TCP_UDP_bidirectional_in_powersave_mode2_lp_TC19490')
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger.info(f"Fetched the device ip address,{device_ip}")
    logger.info(f"*****Enable  Max Power save in DUT******")
    # Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.MaxPowerSave
        )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {bssid}')
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    if protocol == "TCP":
        logger.info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server()
        # DUT opens tcp client socket
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"socket id received is {sock} which is expected")
        logger.info(
            f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # tcp socket opened in DUT connects to the tcp server
        wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    else:
        logger.info("Starting udp socket remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(socket_type=1)
        # Open UDP socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, "socket id received is not matched. Expected is 0"
        logger.info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    tx_rx_obj = tx_rx()
    if protocol == "TCP":
        th_start = Thread(target=tx_rx_obj.receive_data_socket,
                          args=(remote_socket, logger, number_of_pkts, data_size, 0), )
        th_start1 = Thread(target=tx_rx_obj.send_data, args=(remote_socket, logger, data_size, test_run_time, 0), )
    else:
        th_start = Thread(target=tx_rx_obj.receive_data_socket,
                          args=(remote_socket, logger, number_of_pkts, data_size, 1), )
        th_start1 = Thread(target=tx_rx_obj.send_data,
                           args=(remote_socket, logger, data_size, test_run_time, 1, device_ip, local_port), )

    th_start.start()
    th_start1.start()
    time.sleep(1)
    with TimeMeasurer() as t:
        if protocol == "TCP":
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts)
        else:
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                                 server_ip="192.168.50.81", server_port=5001)
    tx_time = t.duration
    logger.info(f"Number of bytes sent by dut {bytes_sent}")
    delta_time = 5
    time.sleep(test_run_time - tx_time + delta_time)
    th_start.join(5)
    th_start1.join(5)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
    bytes_received = int(result.split(b":")[1])
    logger.info(f"bytes received on socket {sock} -> {bytes_received}")
    assert bytes_sent == tx_rx_obj.rcv_data, "Number of bytes sent by DUT and received on remote socket are not " \
                                             "matched "
    packet_loss = (((tx_rx_obj.sent_data - bytes_received) / tx_rx_obj.sent_data) * 100)
    logger.info(f"Packet loss {packet_loss}")
    assert packet_loss < 20, "Packet loss is not in tolerance level while DUT receiving the data"

    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)
    logger.info("Successfully closed opened socket in the DUT")
    logger.info("validate NULL data frame with PM bit set to '1'")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit set to 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.TCP_IP_BI_DIR_ACK_UPDATE,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.firmware_app("test_wlan_powersave_mode3_lp")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.parametrize("protocol", ["TCP", "UDP"])
@pytest.mark.parametrize("number_of_pkts", [1000])
@pytest.mark.parametrize("test_run_time", [200])
def test_TCP_UDP_bidirectional_in_powersave_mode3_lp_TC19493(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point,
                                                             logger, number_of_pkts, protocol, test_run_time):
    data_size = 1460
    remote_socket.interfaces.socket.time_limit = 1800
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_TCP_UDP_bidirectional_in_powersave_mode3_lp_TC19493')
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger.info(f"Fetched the device ip address,{device_ip}")
    logger.info(f"*****Enable  Max Power save in DUT******")
    # Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.MaxPowerSave
        )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {bssid}')
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    if protocol == "TCP":
        logger.info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server()
        # DUT opens tcp client socket
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"socket id received is {sock} which is expected")
        logger.info(
            f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # tcp socket opened in DUT connects to the tcp server
        wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    else:
        logger.info("Starting udp socket remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(socket_type=1)
        # Open UDP socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, "socket id received is not matched. Expected is 0"
        logger.info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    tx_rx_obj = tx_rx()
    if protocol == "TCP":
        th_start = Thread(target=tx_rx_obj.receive_data_socket,
                          args=(remote_socket, logger, number_of_pkts, data_size, 0), )
        th_start1 = Thread(target=tx_rx_obj.send_data, args=(remote_socket, logger, data_size, test_run_time, 0), )
    else:
        th_start = Thread(target=tx_rx_obj.receive_data_socket,
                          args=(remote_socket, logger, number_of_pkts, data_size, 1), )
        th_start1 = Thread(target=tx_rx_obj.send_data,
                           args=(remote_socket, logger, data_size, test_run_time, 1, device_ip, local_port), )

    th_start.start()
    th_start1.start()
    time.sleep(1)
    with TimeMeasurer() as t:
        if protocol == "TCP":
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts)
        else:
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                                 server_ip="192.168.50.81", server_port=5001)
    tx_time = t.duration
    logger.info(f"Number of bytes sent by dut {bytes_sent}")
    delta_time = 5
    time.sleep(test_run_time - tx_time + delta_time)
    th_start.join(5)
    th_start1.join(5)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
    bytes_received = int(result.split(b":")[1])
    logger.info(f"bytes received on socket {sock} -> {bytes_received}")
    assert bytes_sent == tx_rx_obj.rcv_data, "Number of bytes sent by DUT and received on remote socket are not " \
                                             "matched "
    packet_loss = (((tx_rx_obj.sent_data - bytes_received) / tx_rx_obj.sent_data) * 100)
    logger.info(f"Packet loss {packet_loss}")
    assert packet_loss < 20, "Packet loss is not in tolerance level while DUT receiving the data"

    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)
    logger.info("Successfully closed opened socket in the DUT")
    logger.info("validate NULL data frame with PM bit set to '1'")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit set to 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.TCP_IP_BI_DIR_ACK_UPDATE,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.parametrize("protocol", ["TCP", "UDP"])
@pytest.mark.parametrize("number_of_pkts", [1000])
@pytest.mark.parametrize("test_run_time", [200])
def test_TCP_UDP_bidirectional_in_powersave_mode2_ulp_TC19494(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point,
                                                              logger, number_of_pkts, protocol, test_run_time):
    data_size = 1460
    remote_socket.interfaces.socket.time_limit = 1800
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_TCP_UDP_bidirectional_in_powersave_mode2_ulp_TC19494')
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger.info(f"Fetched the device ip address,{device_ip}")
    logger.info(f"*****Enable  Max Power save in DUT******")
    # Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.MaxPowerSave
        )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {bssid}')
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    if protocol == "TCP":
        logger.info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server()
        # DUT opens tcp client socket
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"socket id received is {sock} which is expected")
        logger.info(
            f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # tcp socket opened in DUT connects to the tcp server
        wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    else:
        logger.info("Starting udp socket remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(socket_type=1)
        # Open UDP socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, "socket id received is not matched. Expected is 0"
        logger.info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    tx_rx_obj = tx_rx()
    if protocol == "TCP":
        th_start = Thread(target=tx_rx_obj.receive_data_socket,
                          args=(remote_socket, logger, number_of_pkts, data_size, 0), )
        th_start1 = Thread(target=tx_rx_obj.send_data, args=(remote_socket, logger, data_size, test_run_time, 0), )
    else:
        th_start = Thread(target=tx_rx_obj.receive_data_socket,
                          args=(remote_socket, logger, number_of_pkts, data_size, 1), )
        th_start1 = Thread(target=tx_rx_obj.send_data,
                           args=(remote_socket, logger, data_size, test_run_time, 1, device_ip, local_port), )

    th_start.start()
    th_start1.start()
    time.sleep(1)
    with TimeMeasurer() as t:
        if protocol == "TCP":
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts)
        else:
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                                 server_ip="192.168.50.81", server_port=5001)
    tx_time = t.duration
    logger.info(f"Number of bytes sent by dut {bytes_sent}")
    delta_time = 5
    time.sleep(test_run_time - tx_time + delta_time)
    th_start.join(5)
    th_start1.join(5)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
    bytes_received = int(result.split(b":")[1])
    logger.info(f"bytes received on socket {sock} -> {bytes_received}")
    assert bytes_sent == tx_rx_obj.rcv_data, "Number of bytes sent by DUT and received on remote socket are not " \
                                             "matched "
    packet_loss = (((tx_rx_obj.sent_data - bytes_received) / tx_rx_obj.sent_data) * 100)
    logger.info(f"Packet loss {packet_loss}")
    assert packet_loss < 20, "Packet loss is not in tolerance level while DUT receiving the data"

    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)
    logger.info("Successfully closed opened socket in the DUT")
    logger.info("validate NULL data frame with PM bit set to '1'")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit set to 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.TCP_IP_BI_DIR_ACK_UPDATE,
        "band": 0,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.parametrize("protocol", ["TCP", "UDP"])
@pytest.mark.parametrize("number_of_pkts", [1000])
@pytest.mark.parametrize("test_run_time", [200])
def test_TCP_UDP_bidirectional_in_powersave_mode3_ulp_TC19497(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point,
                                                              logger, number_of_pkts, protocol, test_run_time):
    data_size = 1460
    remote_socket.interfaces.socket.time_limit = 1800
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_TCP_UDP_bidirectional_in_powersave_mode3_ulp_TC19497')
    result_scan = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert result_scan is not None, "No AP found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger.info(f"Fetched the device ip address,{device_ip}")
    logger.info(f"*****Enable  Max Power save in DUT******")
    # Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.MaxPowerSave
        )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {bssid}')
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    if protocol == "TCP":
        logger.info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server()
        # DUT opens tcp client socket
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"socket id received is {sock} which is expected")
        logger.info(
            f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # tcp socket opened in DUT connects to the tcp server
        wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    else:
        logger.info("Starting udp socket remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(socket_type=1)
        # Open UDP socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, "socket id received is not matched. Expected is 0"
        logger.info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    tx_rx_obj = tx_rx()
    if protocol == "TCP":
        th_start = Thread(target=tx_rx_obj.receive_data_socket,
                          args=(remote_socket, logger, number_of_pkts, data_size, 0), )
        th_start1 = Thread(target=tx_rx_obj.send_data, args=(remote_socket, logger, data_size, test_run_time, 0), )
    else:
        th_start = Thread(target=tx_rx_obj.receive_data_socket,
                          args=(remote_socket, logger, number_of_pkts, data_size, 1), )
        th_start1 = Thread(target=tx_rx_obj.send_data,
                           args=(remote_socket, logger, data_size, test_run_time, 1, device_ip, local_port), )

    th_start.start()
    th_start1.start()
    time.sleep(1)
    with TimeMeasurer() as t:
        if protocol == "TCP":
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts)
        else:
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                                 server_ip="192.168.50.81", server_port=5001)
    tx_time = t.duration
    logger.info(f"Number of bytes sent by dut {bytes_sent}")
    delta_time = 5
    time.sleep(test_run_time - tx_time + delta_time)
    th_start.join(5)
    th_start1.join(5)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
    bytes_received = int(result.split(b":")[1])
    logger.info(f"bytes received on socket {sock} -> {bytes_received}")
    assert bytes_sent == tx_rx_obj.rcv_data, "Number of bytes sent by DUT and received on remote socket are not " \
                                             "matched "
    packet_loss = (((tx_rx_obj.sent_data - bytes_received) / tx_rx_obj.sent_data) * 100)
    logger.info(f"Packet loss {packet_loss}")
    assert packet_loss < 20, "Packet loss is not in tolerance level while DUT receiving the data"

    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)
    logger.info("Successfully closed opened socket in the DUT")
    logger.info("validate NULL data frame with PM bit set to '1'")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit set to 1'
