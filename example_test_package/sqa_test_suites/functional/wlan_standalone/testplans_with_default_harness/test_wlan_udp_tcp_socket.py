import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    DeviceConstants,
    RS9116AsyncEventType,
    RS9116PowerSaveProcedureTypes,
    RS9116CustomFeatureBitMap
)
from utf.interfaces.wifi import WlanError
from utf.interfaces.cli import CLITransportException
from threading import Thread
import threading
import string
import random
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
import math
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.thread_base import ThreadBase
from utf.interfaces.socket import SOCKET_TYPE_TCP, SOCKET_TYPE_UDP
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, ping
from utf.utils.subprocess_manager import SubprocessManager

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP or UDP socket
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC device for Sniffer
"""
'''Author: Vivek'''


def logger():
    return get_logger(__name__)


def get_socket_id(sock_fd):
    return int(math.log2(sock_fd))


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


class tx_rx:
    def __init__(self):
        # self.thread_lock = threading.Lock()
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

    def send_data(self, remote_socket, data_size, test_run_time=300, proto_type=0, server_ip=None,
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


class WifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut, net_perf_client, protocol, device_ip, host_ip, time_out):
        super().__init__()
        self.iperf_obj = RunTraffic()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.device_ip = device_ip
        self.host_ip = host_ip
        self.time_out = time_out

    def run(self):
        self.iperf_obj.start_iperf_dut_as_client(self.wifi_dut, self.net_perf_client, self.protocol, self.device_ip, self.host_ip, self.time_out)


class RunTraffic:
    def start_iperf_dut_as_client(self, wifi_dut, net_perf_client, protocol, device_ip, host_ip, time_out):
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                        device_ip=device_ip, protocol=protocol, time_out=time_out)

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
        assert tp is not None
        if tp is not None:
            print_dict("##     ", tp)


class AccessPointApOnOff(ThreadBase):
    def __init__(self, wifi_access_point):
        super().__init__()
        self.wifi_access_point = wifi_access_point

    def run(self):
        logger().info('******* Disable the AP radio **********')
        self.wifi_access_point.interfaces.wifi.stop_ap()
        logger().info('******* Enable the AP radio **********')
        self.wifi_access_point.interfaces.wifi.start_ap()


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE, "mss_value": '1000', "tcp_window_size": '1460'})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "client_socket_limit": 10,
    }
)
def test_socket_tcp_data_transfer_mss_c19357(wifi_access_point, wifi_dut, wifi_client, net_perf_client,
                                                protocol):
    time_out = 10
    send_traffic = RunTraffic()

    '''Send TCP data size with more than MSS'''
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    result = wifi_dut.interfaces.wifi.start_ip()
    device_ip = result.ip.decode()
    logger().info(f"DUT ip address: {device_ip}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    with pytest.raises(WlanError) as exc_info:
        ''' Start Iperf traffic DUT as a client and Linux machine as a server'''
        send_traffic.start_iperf_dut_as_client(wifi_dut, net_perf_client, protocol, device_ip, host_ip, time_out)
    assert exc_info.value.error_code == 0x005A, "observed wrong error code expected is 0x005A"