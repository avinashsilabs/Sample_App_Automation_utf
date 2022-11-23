import pytest
from test_wlan_max_psp_functionality import FilterPacket
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
                                            SocketOptions, RS9116CertificateType,
                                            RS9116JoinFeatureBitMap,
                                            RS9116ULPModes
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
from utf.utils import mac_address_to_string
from utf.interfaces.switch import Switch


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

pdu_state = False

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
        if proto_type == 0:
            remote_socket.interfaces.socket.set_recv_timeout(socket_type=0)
        else:
            remote_socket.interfaces.socket.set_recv_timeout(use_client_socket=True, socket_type=1)
        for count in range(0, no_of_pkts):
            if proto_type == 0:
                data = remote_socket.interfaces.socket.recv_data_tcp(data_size)
            else:
                data, address = remote_socket.interfaces.socket.recv_data_udp(data_size)
            if not isinstance(data, str):
                fail_count = fail_count + 1
                if fail_count == 5:
                    break
                else:
                    continue
            self.rcv_data = self.rcv_data + len(data)
        logger().info(f"Total bytes received on socket opened remotely -> {self.rcv_data}")

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
        logger().info(f"Total bytes sent on socket opened remotely -> {self.sent_data}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
                                                                         test_run_time, rs_helper, utf_constants):
    logger().info(f"The test case will be executed for {test_run_time} seconds")
    sw = Stopwatch()
    iteration = 0
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    while sw.elapsed_sec < test_run_time:
        iteration = iteration + 1
        logger().info(f"#####################################################Iteration count -> {iteration}")
        validation = True
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_connect_and_disconnect_when_module_is_in_power_save_mode_C19485')
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        time.sleep(30)
        # Add disconnect.leave api
        wifi_dut.interfaces.wifi.leave()
        logger().info("validate NULL data frame with PM bit set to '1'")
        logger().info("Verifying powersave mode 2 bit")
        packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) ' \
                         f'and (wlan.sa == {dut_mac_address}) ' \
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode1_C19486(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut,
                                                            wifi_client,
                                                            rs_helper, utf_constants):
    validation = True
    capture_filename = "test_TCP_UDP_Rx_data_transfer_in_powersave_mode1_C19486"

    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=False)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")


    # Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1,
                                                 RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')

    timeout = 300
    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    for protocol in protocols:
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")

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
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.LPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.firmware_app("test_wlan_powersave_mode2_lp")
@pytest.mark.skip()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
def test_TCP_UDP_Tx_data_transfer_in_powersave_mode2_lp_C19488(firmware_loader, net_perf_client, wifi_sniffer,
                                                               wifi_access_point, wifi_dut,
                                                               wifi_client,
                                                               utf_constants, rs_helper):
    validation = True
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    capture_filename = "test_TCP_UDP_Tx_data_transfer_in_powersave_mode2_lp_C19488"
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")
    timeout = 200

    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    for protocol in protocols:
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.firmware_app("test_wlan_powersave_mode2_lp")
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.skip()
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode2_lp_C19489(firmware_loader, net_perf_client, wifi_sniffer,
                                                               wifi_access_point, wifi_dut,
                                                               wifi_client,
                                                               rs_helper, utf_constants):
    validation = True
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    capture_filename = "test_TCP_UDP_Rx_data_transfer_in_powersave_mode2_lp_C19489"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")
    timeout = 200
    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    for protocol in protocols:
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")


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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.firmware_app("test_wlan_powersave_mode3_lp")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
def test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_lp_C19491(firmware_loader, net_perf_client, wifi_sniffer,
                                                               wifi_access_point, wifi_dut,
                                                               wifi_client,
                                                               rs_helper, utf_constants):
    validation = True
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    capture_filename = "test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_lp_C19491"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    timeout = 300
    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    for protocol in protocols:
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.firmware_app("test_wlan_powersave_mode3_lp")
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_lp_C19492(firmware_loader, net_perf_client, wifi_sniffer,
                                                               wifi_access_point, wifi_dut,
                                                               wifi_client,
                                                               rs_helper, utf_constants):
    validation = True
    capture_filename = "test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_lp_C19492"

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    timeout = 300
    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    for protocol in protocols:
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")

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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
def test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_C19495(firmware_loader, net_perf_client, wifi_sniffer,
                                                            wifi_access_point, wifi_dut,
                                                            wifi_client,
                                                            rs_helper, utf_constants):
    validation = True
    capture_filename = "test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_C19495"

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    timeout = 300
    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    for protocol in protocols:
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_C19496(firmware_loader, net_perf_client, wifi_sniffer,
                                                            wifi_access_point, wifi_dut,
                                                            wifi_client,
                                                            rs_helper, utf_constants):
    validation = True
    capture_filename = "test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_C19496"
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    timeout = 300
    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    for protocol in protocols:
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")


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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_powersave_disable_functionality_powersave1_C19501(wifi_access_point, wifi_dut, wifi_sniffer, rs_helper,
                                                           utf_constants):
    validation = True
    capture_filename = "test_powersave_disable_functionality_powersave1_C19501"

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=False)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    logger().info(f"*****Enable Powersave1 in  DUT******")
    # Initiating power save2
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_powersave_disable_functionality_powersave2_C19501(wifi_access_point, wifi_dut, wifi_sniffer, rs_helper, utf_constants):
    validation = True
    capture_filename = "test_powersave_disable_functionality_powersave2_C19501"

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=False)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    logger().info(f"*****Enable Powersave1 in  DUT******")
    # Initiating power save2
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_powersave_disable_functionality_powersave3_C19501(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer,
                                                           rs_helper, utf_constants):
    validation = True
    capture_filename = "test_powersave_disable_functionality_powersave3_C19501"

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=False)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    logger().info(f"*****Enable Powersave1 in  DUT******")
    # Initiating power save2
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.TCP_ACK_CORRECT,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.parametrize("number_of_pkts", [1000])
@pytest.mark.parametrize("test_run_time", [200])
def test_TCP_UDP_bidirectional_in_powersave_mode1_TC19487(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point,
                                                          number_of_pkts, test_run_time,
                                                          rs_helper, utf_constants):
    data_size = 1460
    remote_socket.interfaces.socket.time_limit = 1800
    validation = True
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    capture_filename = "test_TCP_UDP_bidirectional_in_powersave_mode1_TC19487"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=False)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    # Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1,
                                                 RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert result is not None, "Powersave Command Failed"
    wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
    protocols = ["TCP", "UDP"]
    for protocol in protocols:
        if protocol == "TCP":
            logger().info("Starting tcp server remotely at port number 5001")
            remote_socket.interfaces.socket.start_server()
            # DUT opens tcp client socket
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, f"socket id received is wrong, expected is 0"
            logger().info(f"socket id received is {sock} which is expected")
            logger().info(
                f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
            local_port = randint(5001, 60000)
            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            # tcp socket opened in DUT connects to the tcp server
            wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
        else:
            logger().info("Starting udp socket remotely at port number 5001")
            remote_socket.interfaces.socket.start_server(socket_type=1)
            # Open UDP socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, "socket id received is not matched. Expected is 0"
            logger().info(f"socket id received is {sock} which is expected")
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
                server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
                server_port = remote_socket.interfaces.socket.server_port
                bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                                     server_ip=server_ip, server_port=server_port)
        tx_time = t.duration
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        delta_time = 5
        time.sleep(test_run_time - tx_time + delta_time)
        th_start.join(5)
        th_start1.join(5)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
        bytes_received = int(result.split(b":")[1])
        logger().info(f"bytes received on socket {sock} -> {bytes_received}")
        if protocol == "TCP":
            assert bytes_sent == tx_rx_obj.rcv_data, "Number of bytes sent by DUT and received on remote socket are not " \
                                                     "matched "
        else:
            packet_loss_tx = (((bytes_sent - tx_rx_obj.rcv_data) / bytes_sent) * 100)
            assert packet_loss_tx < 20, "Packet loss is not in tolerance level while DUT is sending data over UDP"
        packet_loss = (((tx_rx_obj.sent_data - bytes_received) / tx_rx_obj.sent_data) * 100)
        logger().info(f"Packet loss {packet_loss}")
        assert packet_loss < 20, "Packet loss is not in tolerance level while DUT receiving the data"

        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket"
        remote_socket.interfaces.socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.TCP_ACK_CORRECT,
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
                                                             number_of_pkts, protocol, test_run_time,
                                                             rs_helper, utf_constants):
    data_size = 1460
    remote_socket.interfaces.socket.time_limit = 1800
    validation = True
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    capture_filename = "test_TCP_UDP_bidirectional_in_powersave_mode2_lp_TC19490"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    if protocol == "TCP":
        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server()
        # DUT opens tcp client socket
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
        logger().info(
            f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # tcp socket opened in DUT connects to the tcp server
        wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    else:
        logger().info("Starting udp socket remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(socket_type=1)
        # Open UDP socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, "socket id received is not matched. Expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
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
            server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
            server_port = remote_socket.interfaces.socket.server_port
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                                 server_ip=server_ip, server_port=server_port)
    tx_time = t.duration
    logger().info(f"Number of bytes sent by dut {bytes_sent}")
    delta_time = 5
    time.sleep(test_run_time - tx_time + delta_time)
    th_start.join(5)
    th_start1.join(5)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
    bytes_received = int(result.split(b":")[1])
    logger().info(f"bytes received on socket {sock} -> {bytes_received}")
    if protocol == "TCP":
        assert bytes_sent == tx_rx_obj.rcv_data, "Number of bytes sent by DUT and received on remote socket are not " \
                                                 "matched "
    else:
        packet_loss_tx = (((bytes_sent - tx_rx_obj.rcv_data) / bytes_sent) * 100)
        assert packet_loss_tx < 20, "Packet loss is not in tolerance level while DUT is sending data over UDP"

    packet_loss = (((tx_rx_obj.sent_data - bytes_received) / tx_rx_obj.sent_data) * 100)
    logger().info(f"Packet loss {packet_loss}")
    assert packet_loss < 20, "Packet loss is not in tolerance level while DUT receiving the data"

    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)
    logger().info("Successfully closed opened socket in the DUT")
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.TCP_ACK_CORRECT,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.firmware_app("test_wlan_powersave_mode3_lp")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.parametrize("number_of_pkts", [1000])
@pytest.mark.parametrize("test_run_time", [200])
def test_TCP_UDP_bidirectional_in_powersave_mode3_lp_TC19493(firmware_loader, wifi_sniffer, remote_socket, wifi_dut,
                                                             wifi_access_point,
                                                             number_of_pkts, test_run_time,
                                                             rs_helper, utf_constants):
    data_size = 1460
    remote_socket.interfaces.socket.time_limit = 1800
    validation = True
    capture_filename = "test_TCP_UDP_bidirectional_in_powersave_mode3_lp_TC19493"

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    protocols = ["TCP", "UDP"]
    for protocol in protocols:

        if protocol == "TCP":
            logger().info("Starting tcp server remotely at port number 5001")
            remote_socket.interfaces.socket.start_server()
            # DUT opens tcp client socket
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, f"socket id received is wrong, expected is 0"
            logger().info(f"socket id received is {sock} which is expected")
            logger().info(
                f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
            local_port = randint(5001, 60000)
            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            # tcp socket opened in DUT connects to the tcp server
            wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
        else:
            logger().info("Starting udp socket remotely at port number 5001")
            remote_socket.interfaces.socket.start_server(socket_type=1)
            # Open UDP socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, "socket id received is not matched. Expected is 0"
            logger().info(f"socket id received is {sock} which is expected")
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
                server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
                server_port = remote_socket.interfaces.socket.server_port
                bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                                     server_ip=server_ip, server_port=server_port)
        tx_time = t.duration
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        delta_time = 5
        time.sleep(test_run_time - tx_time + delta_time)
        th_start.join(5)
        th_start1.join(5)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
        bytes_received = int(result.split(b":")[1])
        logger().info(f"bytes received on socket {sock} -> {bytes_received}")
        if protocol == "TCP":
            assert bytes_sent == tx_rx_obj.rcv_data, "Number of bytes sent by DUT and received on remote socket are not " \
                                                     "matched "
        else:
            packet_loss_tx = (((bytes_sent - tx_rx_obj.rcv_data) / bytes_sent) * 100)
            assert packet_loss_tx < 20, "Packet loss is not in tolerance level while DUT is sending data over UDP"
        packet_loss = (((tx_rx_obj.sent_data - bytes_received) / tx_rx_obj.sent_data) * 100)
        logger().info(f"Packet loss {packet_loss}")
        assert packet_loss < 20, "Packet loss is not in tolerance level while DUT receiving the data"

        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket"
        remote_socket.interfaces.socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")
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
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.TCP_ACK_CORRECT,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.parametrize("number_of_pkts", [1000])
@pytest.mark.parametrize("test_run_time", [200])
def test_TCP_UDP_bidirectional_in_powersave_mode2_ulp_TC19494(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point,
                                                              number_of_pkts, test_run_time,
                                                              rs_helper, utf_constants):
    data_size = 1460
    remote_socket.interfaces.socket.time_limit = 1800
    validation = True

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    capture_filename = "test_TCP_UDP_bidirectional_in_powersave_mode2_ulp_TC19494"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    protocols = ["TCP", "UDP"]
    for protocol in protocols:

        if protocol == "TCP":
            logger().info("Starting tcp server remotely at port number 5001")
            remote_socket.interfaces.socket.start_server()
            # DUT opens tcp client socket
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, f"socket id received is wrong, expected is 0"
            logger().info(f"socket id received is {sock} which is expected")
            logger().info(
                f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
            local_port = randint(5001, 60000)
            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            # tcp socket opened in DUT connects to the tcp server
            wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
        else:
            logger().info("Starting udp socket remotely at port number 5001")
            remote_socket.interfaces.socket.start_server(socket_type=1)
            # Open UDP socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, "socket id received is not matched. Expected is 0"
            logger().info(f"socket id received is {sock} which is expected")
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
                server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
                server_port = remote_socket.interfaces.socket.server_port
                bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                                     server_ip=server_ip, server_port=server_port)
        tx_time = t.duration
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        delta_time = 5
        time.sleep(test_run_time - tx_time + delta_time)
        th_start.join(5)
        th_start1.join(5)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
        bytes_received = int(result.split(b":")[1])
        logger().info(f"bytes received on socket {sock} -> {bytes_received}")
        if protocol == "TCP":
            assert bytes_sent == tx_rx_obj.rcv_data, "Number of bytes sent by DUT and received on remote socket are not " \
                                                     "matched "
        else:
            packet_loss_tx = (((bytes_sent - tx_rx_obj.rcv_data) / bytes_sent) * 100)
            assert packet_loss_tx < 20, "Packet loss is not in tolerance level while DUT is sending data over UDP"
        packet_loss = (((tx_rx_obj.sent_data - bytes_received) / tx_rx_obj.sent_data) * 100)
        logger().info(f"Packet loss {packet_loss}")
        assert packet_loss < 20, "Packet loss is not in tolerance level while DUT receiving the data"

        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket"
        remote_socket.interfaces.socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.TCP_ACK_CORRECT,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.parametrize("number_of_pkts", [1000])
@pytest.mark.parametrize("test_run_time", [200])
def test_TCP_UDP_bidirectional_in_powersave_mode3_ulp_TC19497(firmware_loader, wifi_sniffer, remote_socket, wifi_dut,
                                                              wifi_access_point,
                                                              number_of_pkts, test_run_time,
                                                              rs_helper, utf_constants):
    data_size = 1460
    remote_socket.interfaces.socket.time_limit = 1800
    validation = True
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    capture_filename = "test_TCP_UDP_bidirectional_in_powersave_mode3_ulp_TC19497"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    protocols = ["TCP", "UDP"]
    for protocol in protocols:
        if protocol == "TCP":
            logger().info("Starting tcp server remotely at port number 5001")
            remote_socket.interfaces.socket.start_server()
            # DUT opens tcp client socket
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, f"socket id received is wrong, expected is 0"
            logger().info(f"socket id received is {sock} which is expected")
            logger().info(
                f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
            local_port = randint(5001, 60000)
            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            # tcp socket opened in DUT connects to the tcp server
            wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
        else:
            logger().info("Starting udp socket remotely at port number 5001")
            remote_socket.interfaces.socket.start_server(socket_type=1)
            # Open UDP socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, "socket id received is not matched. Expected is 0"
            logger().info(f"socket id received is {sock} which is expected")
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
                server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
                server_port = remote_socket.interfaces.socket.server_port
                bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                                     server_ip=server_ip, server_port=server_port)
        tx_time = t.duration
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        delta_time = 5
        time.sleep(test_run_time - tx_time + delta_time)
        th_start.join(5)
        th_start1.join(5)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
        bytes_received = int(result.split(b":")[1])
        logger().info(f"bytes received on socket {sock} -> {bytes_received}")
        if protocol == "TCP":
            assert bytes_sent == tx_rx_obj.rcv_data, "Number of bytes sent by DUT and received on remote socket are not " \
                                                     "matched "
        else:
            packet_loss_tx = (((bytes_sent - tx_rx_obj.rcv_data) / bytes_sent) * 100)
            assert packet_loss_tx < 20, "Packet loss is not in tolerance level while DUT is sending data over UDP"
        packet_loss = (((tx_rx_obj.sent_data - bytes_received) / tx_rx_obj.sent_data) * 100)
        logger().info(f"Packet loss {packet_loss}")
        assert packet_loss < 20, "Packet loss is not in tolerance level while DUT receiving the data"

        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket"
        remote_socket.interfaces.socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")
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
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_powersave_mode_2_Enterprise_C19509(radius_server, net_perf_client, protocol,
                                            wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, utf_constants,
                                            rs_helper):
    testcase = "test_powersave_mode_2_Enterprise_C19509"

    iter_count = utf_constants.get("iter_count")
    ping_count = utf_constants.get("ping_count")

    for i in range(0, iter_count):

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")

        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point, eap_type="TLS")
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        timeout = 60

        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")

        protocol = IperfConstants.UDP

        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        validation = True

        packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {ap_bssid}))'

        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit set to 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["multicast_leave", "disassociated", "clear_certs"])
def test_Send_Multicast_Broadcast_data_C19507(multicast_client, net_perf_client, protocol,
                                              wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, utf_constants, rs_helper):
    testcase = "test_Send_Multicast_data_C19507"
    logger().info("configuring the Sniffer with the channel")
    capture_filename = testcase
    iter_count = utf_constants.get("iter_count")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    for i in range(0, iter_count):
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        timeout = 60

        rs_helper.run_multicast_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                        multicast_client, traffic_type="TX")

        rs_helper.run_broadcast_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                        traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        validation = True

        packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {ap_bssid}))'

        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit set to 1'




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
    },
)

@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_powersave_functionality_after_rejoin_C19508(wifi_sniffer, wifi_dut, wifi_access_point, utf_constants, switch, rs_helper):

    validation = True
    global pdu_state
    packet_filter4 = False
    capture_filename = "test_powersave_functionality_after_rejoin_C19508"
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")

    try:
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        logger().info(f'PDU state = {pdu_state}')
        if pdu_state is False:
            switch.interfaces.pdu_switch.turn_on()
            pdu_state = True
            time.sleep(60)

        for i in range(0, iter_count):
            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
            device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
            logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

            logger().info("Stoping the capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            # Validating the power management bit
            packet_filter1 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024)' \
                             f' && (wlan.sa == {dut_mac_address}) && (wlan.da == {ap_bssid}))'

            logger().info(f"validating power save in sniffer with filter {packet_filter1}")

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter1)['packet_count'], \
                'Sniffer validation failed for NULL data frame with PM bit 1'

            # Validate Probe req(Broadcast/Unicast)

            packet_filter2 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                             f'wlan.fc.type_subtype == 0x0004 and (wlan.da == ff:ff:ff:ff:ff:ff)'

            # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
            packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                             f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                             f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

            logger().info("Starting the capture")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_procedure')
            time.sleep(2)
            # wifi_access_point.interfaces.wifi.stop_ap()

            logger().info('***** Turn off Access point *****')
            if pdu_state is True:
                switch.interfaces.pdu_switch.turn_off()
                pdu_state = False
            time.sleep(10)

            logger().info('***** Turn ON Access point *****')
            logger().info(f'PDU state = {pdu_state}')
            if pdu_state is False:
                switch.interfaces.pdu_switch.turn_on()
                pdu_state = True
                time.sleep(60)

            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, ping_count)
            assert status is True, "DUT is not responding to ping request from third party device after rejoin"
            logger().info(f"ping is successful after rejoin")

            logger().info("disconnecting to ap.....")
            wifi_dut.interfaces.wifi.leave()

            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop Sniffer finally")
            time.sleep(5)
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2, packet_filter4)[
                'packet_count'], "Probe requests not found after rejoin"
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter4)[
                'packet_count'], "Association procedure not found in sniffer"

            logger().info(f"validating power save in sniffer with filter {packet_filter1}")

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter1)['packet_count'], \
                'Sniffer validation failed for NULL data frame with PM bit 1'

    finally:
        if pdu_state is False:
            logger().info('\n\n Finally Turn on the AP ')
            switch.interfaces.pdu_switch.turn_on()
            pdu_state = True
            time.sleep(60)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '12345678', "dtim": 3,
                                               "beacon_interval": 100})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["multicast_leave", "disassociated", "clear_certs"])
def test_Multicast_Broadcast_RX_Pwrmode_1_dtim_C19510(multicast_client, net_perf_client, protocol,
                                                      wifi_sniffer, wifi_dut, wifi_client, wifi_access_point,
                                                      utf_constants, rs_helper):
    testcase = "test_Multicast_Broadcast_RX_Pwrmode_1_dtim_C19510"
    logger().info("configuring the Sniffer with the channel")
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    assoc_obj = FilterPacket()
    ps_packet_exchange_obj = FilterPacket()
    dtim = '3'
    capture_filename = testcase
    powersave_validation = True
    iter_count = utf_constants.get("iter_count")
    ping_count = utf_constants.get("ping_count")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    for i in range(0, iter_count):
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                         listen_interval=800)
        logger().info("enabling dhcp in DUT.......")
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=60)
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT ip: {device_ip}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave
        )

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, ping_count)
        assert status, "DUT is not responding to ping request from third party device"

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        timeout = 60
        rs_helper.run_multicast_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                        multicast_client, traffic_type="RX")

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Assoc resp frame in sniffer
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

        validation = True

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
            'packet_count']

        time.sleep(1)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
        packet_filter4 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                         f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                         f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                         f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, None,
                                                                  powersave_validation)['packet_count'], \
            "sniffer validation failed"
        case1, case2, case3, case4 = ps_packet_exchange_obj.dtim_based_validation(association_id)
        if case1 != 0 or case2 != 0 or case3 != 0 or case4 != 0:
            if case1 != 0:
                logger().info(
                    f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
            if case2 != 0:
                logger().info(
                    f'Observed {case2} times DUT is sending PS-POLL at next DTIM beacon even though more data bit set')
            if case3 != 0:
                logger().info(
                    f'Observed {case3} times DUT is not sending PS-POLL at DTIM beacon even though TIM is set')
            if case4 != 0:
                logger().info(
                    f'Observed {case4} times DUT is sending PS-POLL at non-DTIM beacons')
            assert False, "powersave validation failed in sniffer"
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at DTIM beacon only"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        rs_helper.run_broadcast_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                        traffic_type="RX")

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
        packet_filter4 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                         f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                         f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                         f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, None,
                                                                  powersave_validation)['packet_count'],\
            "sniffer validation failed"
        case1, case2, case3, case4 = ps_packet_exchange_obj.dtim_based_validation(association_id)
        if case1 != 0 or case2 != 0 or case3 != 0 or case4 != 0:
            if case1 != 0:
                logger().info(
                    f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
            if case2 != 0:
                logger().info(
                    f'Observed {case2} times DUT is sending PS-POLL at next DTIM beacon even though more data bit set')
            if case3 != 0:
                logger().info(
                    f'Observed {case3} times DUT is not sending PS-POLL at DTIM beacon even though TIM is set')
            if case4 != 0:
                logger().info(
                    f'Observed {case4} times DUT is sending PS-POLL at non-DTIM beacons')
            assert False, "Powersave validation failed in sniffer"
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at DTIM beacon only"

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,#| RS9116FeatureBitMap.ULPGPIOHandshake
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["multicast_leave", "disassociated", "clear_certs"])
@pytest.mark.firmware_app("test_wlan_powersave_mode3_lp")
def test_Pwrmode_3LP_with_diff_dtim_C19506_case_1_and_2(multicast_client, net_perf_client, protocol,
                                                      wifi_sniffer, wifi_dut, wifi_client, wifi_access_point,
                                                      utf_constants, rs_helper):
    testcase = "test_Pwrmode_3LP_with_diff_dtim_C19506"
    logger().info("configuring the Sniffer with the channel")
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    assoc_obj = FilterPacket()
    ps_packet_exchange_obj = FilterPacket()
    capture_filename = testcase
    powersave_validation = True
    iter_count = utf_constants.get("iter_count")
    ping_count = 100 #utf_constants.get("ping_count")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    for i in range(0, iter_count):

        dtim = '10'
        beacon_interval_list = ["100", "1000"]

        for beacon_interval in beacon_interval_list:

            wifi_access_point.interfaces.wifi.config['dtim'] = dtim
            wifi_access_point.interfaces.wifi.config['beacon_interval'] = beacon_interval
            wifi_access_point.interfaces.wifi.start_ap()

            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

            wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=0,
                                             listen_interval=0)
            logger().info("enabling dhcp in DUT.......")
            ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            logger().info(f"DUT ip: {device_ip}")

            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")

            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)
            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, ping_count)
            assert status, "DUT is not responding to ping request from third party device"

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            # Assoc resp frame in sniffer
            packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

            validation = True

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
                'packet_count']

            time.sleep(1)
            association_id = assoc_obj.get_association_id()
            if association_id is None:
                logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
                assert False
            else:
                logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

            # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
            packet_filter4 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                             f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                             f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                             f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, None,
                                                                      powersave_validation)['packet_count'],\
                "sniffer validation failed"
            case1, case2, case3, case4 = ps_packet_exchange_obj.dtim_based_validation(association_id)
            if case1 != 0 or case2 != 0 or case3 != 0 or case4 != 0:
                if case1 != 0:
                    logger().info(
                        f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
                if case2 != 0:
                    logger().info(
                        f'Observed {case2} times DUT is sending PS-POLL at next DTIM beacon even though more data bit set')
                if case3 != 0:
                    logger().info(
                        f'Observed {case3} times DUT is not sending PS-POLL at DTIM beacon even though TIM is set')
                if case4 != 0:
                    logger().info(
                        f'Observed {case4} times DUT is sending PS-POLL at non-DTIM beacons')
                assert False, "powersave validation failed in sniffer"
            else:
                assert True, "DUT is sending PS-POLL to retrieve the data at DTIM beacon only"

            logger().info("Initiating disconnect from DUT")
            # Wlan Disconnect
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["multicast_leave", "disassociated", "clear_certs"])
@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
def test_Pwrmode_3ULP_with_diff_dtim_C19506_case_3_and_4(firmware_loader, multicast_client, net_perf_client, protocol,
                                                        wifi_sniffer, wifi_dut, wifi_client, wifi_access_point,
                                                        utf_constants, rs_helper):
    testcase = "test_Pwrmode_3ULP_with_diff_dtim_C19506_case_3_and_4"
    logger().info("configuring the Sniffer with the channel")
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    assoc_obj = FilterPacket()
    ps_packet_exchange_obj = FilterPacket()
    capture_filename = testcase
    powersave_validation = True
    iter_count = utf_constants.get("iter_count")
    ping_count = 100  # utf_constants.get("ping_count")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    for i in range(0, iter_count):

        dtim = '10'
        beacon_interval_list = ["100", "1000"]

        for beacon_interval in beacon_interval_list:

            wifi_access_point.interfaces.wifi.config['dtim'] = dtim
            wifi_access_point.interfaces.wifi.config['beacon_interval'] = beacon_interval
            wifi_access_point.interfaces.wifi.start_ap()

            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

            wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=0,
                                             listen_interval=0)
            logger().info("enabling dhcp in DUT.......")
            ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            logger().info(f"DUT ip: {device_ip}")

            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")

            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)
            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, ping_count)
            assert status, "DUT is not responding to ping request from third party device"

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            # Assoc resp frame in sniffer
            packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

            validation = True

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
                'packet_count']

            time.sleep(1)
            association_id = assoc_obj.get_association_id()
            if association_id is None:
                logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
                assert False, f'Unable to find ASSOCIATION-ID={association_id}'
            else:
                logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

            # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
            packet_filter4 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                             f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                             f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                             f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, None,
                                                                      powersave_validation)['packet_count'],\
                "sniffer validation failed"
            case1, case2, case3, case4 = ps_packet_exchange_obj.dtim_based_validation(association_id)
            if case1 != 0 or case2 != 0 or case3 != 0 or case4 != 0:
                if case1 != 0:
                    logger().info(
                        f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
                if case2 != 0:
                    logger().info(
                        f'Observed {case2} times DUT is sending PS-POLL at next DTIM beacon even though more data bit set')
                if case3 != 0:
                    logger().info(
                        f'Observed {case3} times DUT is not sending PS-POLL at DTIM beacon even though TIM is set')
                if case4 != 0:
                    logger().info(
                        f'Observed {case4} times DUT is sending PS-POLL at non-DTIM beacons')
                assert False, "Powersave validation failed in sniffer"
            else:
                assert True, "DUT is sending PS-POLL to retrieve the data at DTIM beacon only"

            logger().info("Initiating disconnect from DUT")
            # Wlan Disconnect
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
#@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
def test_Pwrmode_8_with_ULP_C19504(wifi_sniffer, wifi_dut, wifi_access_point,
                                   utf_constants, rs_helper):
    testcase = "test_Pwrmode_8_with_ULP_C19504"
    logger().info("configuring the Sniffer with the channel")
    capture_filename = testcase
    iter_count = utf_constants.get("iter_count")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    for i in range(0, iter_count):
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)

        # Enables the bt power save in DUT
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        time.sleep(120)

        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)

        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        assert (len(scan_results) >= 1), "Scan failed"
        logger().info(scan_results)
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '12345678'})
@pytest.mark.dut("rs9116")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_Pwrmode_9_with_LP_C19503(wifi_sniffer, wifi_dut, wifi_access_point, utf_constants):
    testcase = "test_Pwrmode_9_with_LP_C19503"
    logger().info("configuring the Sniffer with the channel")
    capture_filename = testcase
    iter_count = utf_constants.get("iter_count")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

    wifi_dut.interfaces.wifi.reset_mode = "hard"
    wifi_dut.interfaces.wifi.reset()
    wifi_dut.interfaces.wifi.init()
    logger().info("Setting DUT in wlan power save...")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode9,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave,
                                            RS9116ULPModes.PowerSaveDisabled)

        wifi_dut.interfaces.wifi.issue_ack()
    logger().info(f"test executed in {t.duration} seconds")
    time_taken = int(t.duration)
    assert time_taken % 3 == 0, "time taken for WKP is not multiple of 3"
    logger().info(f"time taken for WKP is multiple of 3")

    logger().info("Initiating scan from dut...")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel_list=0)
    assert (len(scan_results) >= 1), "Scan failed"
    logger().info(scan_results)

    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)

    wifi_dut.interfaces.wifi.set_sleep_timer(time_value=10)
    logger().info("Setting DUT in wlan power save...")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode9,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave,
                                            RS9116ULPModes.PowerSaveDisabled)

        wifi_dut.interfaces.wifi.issue_ack()
    logger().info(f"test executed in {t.duration} seconds")

    time_taken = int(t.duration)
    assert time_taken % 10 == 0, "time taken for WKP is not multiple of 10"
    logger().info(f"time taken for WKP is multiple of 10")

    logger().info("Initiating scan from dut...")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel_list=0)
    assert (len(scan_results) >= 1), "Scan failed"
    logger().info(scan_results)

    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '12345678'})
@pytest.mark.dut("rs9116")
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_Pwrmode_9_with_ULP_C19505(wifi_sniffer, wifi_dut, wifi_access_point, utf_constants):
    testcase = "test_Pwrmode_9_with_ULP_C19505"
    logger().info("configuring the Sniffer with the channel")
    capture_filename = testcase
    iter_count = utf_constants.get("iter_count")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

    wifi_dut.interfaces.wifi.reset_mode = "hard"
    wifi_dut.interfaces.wifi.reset()
    wifi_dut.interfaces.wifi.init()
    logger().info("Setting DUT in wlan power save...")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode9,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave,
                                            RS9116ULPModes.ULPModeWithRAMRetention)

        wifi_dut.interfaces.wifi.issue_ack()
    logger().info(f"test executed in {t.duration} seconds")
    time_taken = int(t.duration)
    assert time_taken % 3 == 0, "time taken for WKP is not multiple of 3"
    logger().info(f"time taken for WKP is multiple of 3")

    logger().info("Initiating scan from dut...")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel_list=0)
    assert (len(scan_results) >= 1), "Scan failed"
    logger().info(scan_results)

    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)

    wifi_dut.interfaces.wifi.set_sleep_timer(time_value=10)
    logger().info("Setting DUT in wlan power save...")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode9,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave,
                                            RS9116ULPModes.ULPModeWithRAMRetention)

        wifi_dut.interfaces.wifi.issue_ack()
    logger().info(f"test executed in {t.duration} seconds")

    time_taken = int(t.duration)
    assert time_taken % 10 == 0, "time taken for WKP is not multiple of 10"
    logger().info(f"time taken for WKP is multiple of 10")

    logger().info("Initiating scan from dut...")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel_list=0)
    assert (len(scan_results) >= 1), "Scan failed"
    logger().info(scan_results)

    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.dut("rs9116")
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                      wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_power_mode3_slp_ack_TCP_UDP_TX_C19498(wifi_sniffer, wifi_access_point, wifi_dut, net_perf_client, protocol,
                                               wifi_client, utf_constants, rs_helper):
        testcase = "test_power_mode3_slp_ack_TCP_UDP_TX_C19498"
        capture_filename = testcase
        timeout = 30
        validation = True
        iter_count = utf_constants.get("iter_count")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {ap_bssid}")

        wifi_dut.interfaces.wifi.reset_mode = "hard"
        wifi_dut.interfaces.wifi.reset()

        wifi_dut.interfaces.wifi.inited = False
        wifi_dut.interfaces.wifi.init()

        for i in range(iter_count):

            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

            device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      power_save=False)
            logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

            wifi_dut.interfaces.wifi.power_save(
                RS9116PowerSaveModes.PowerSaveMode3, RS9116PowerSaveProcedureTypes.FastPowerSave
            )
            wifi_dut.interfaces.wifi.issue_ack()

            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{host_ip}")

            protocols = [IperfConstants.TCP, IperfConstants.UDP]
            for protocol in protocols:
                rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                      traffic_type="TX")

            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)

            logger().info("stopping the capture")
            # Stop Sniffer
            wifi_sniffer.interfaces.capture.stop_capture()

            # Validating the power management bit
            packet_filter1 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024)' \
                             f' && (wlan.sa == {dut_mac_address}) && (wlan.da == {ap_bssid}))'

            logger().info(f"validating power save in sniffer with filter {packet_filter1}")

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter1)['packet_count'], \
                'Sniffer validation failed for NULL data frame with PM bit 1'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.dut("rs9116")
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                      wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_power_mode_switching_before_assoc_C19500(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants):

        testcase = "test_power_mode_switching_before_assoc_C19500"
        capture_filename = testcase
        validation = True
        iter_count = utf_constants.get("iter_count")
        ping_count = utf_constants.get("ping_count")
        time.sleep(5)

        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        wifi_dut.interfaces.wifi.reset_mode = "hard"

        for k in range(0, 2):
            try:
                wifi_dut.interfaces.wifi.reset()
            except:
                logger().info("reset failed trying for 2 times")
                if k == 2:
                    raise
        wifi_dut.interfaces.wifi.init()

        for i in range(0, iter_count):

            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

            wifi_dut.interfaces.wifi.power_save(0)
            logger().info("scan for the ap's.....")
            wifi_dut.interfaces.wifi.scan(ssid=wifi_access_point.interfaces.wifi.ssid)

        wifi_dut.interfaces.wifi.reset_mode = "hard"
        wifi_dut.interfaces.wifi.reset()
        wifi_dut.interfaces.wifi.init()

        for i in range(0, iter_count):

            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode9,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave
                                                )

            time.sleep(3)
            wifi_dut.interfaces.wifi.power_save(0)
            logger().info("scan for the ap's.....")
            wifi_dut.interfaces.wifi.scan(ssid=wifi_access_point.interfaces.wifi.ssid)

        logger().info("stopping the capture")
        # Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()
