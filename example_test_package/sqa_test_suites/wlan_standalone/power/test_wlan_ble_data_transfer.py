import time
import pytest

from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116PowerSaveModes,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116TCPIPFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116BLEFeatureBitMap,
    RS9116BTFeatureBitMap,
    RS9116JoinFeatureBitMap,
    SocketOptions,
    SocketType,
    Cipher,
    DeviceConstants,

)
import string
import random
from utf.interfaces.wifi import WlanError
from utf.utils.iperf.iperf_utils import ping
from random import randint
from datetime import datetime
from typing import Dict
import uuid
from threading import Thread
import threading
from utf.utils import get_tls_certificate_dir
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType

def logger():
    return get_logger(__name__)

def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)
"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in Wifi+Bluetooth dual mode
        2. Put DUT in BLE advertising mode
        3. Put RaspberryPi in scan mode
        4. Initiate connection from Raspberry pi over BLE
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
"""
"""Author : Aravind"""


class device_scan_result:
    def check_for_devices_in_scanned_results(self, ble_client, bt_dut_address, adv_data):
        sw = Stopwatch()
        previously_found_devices = {}
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            if previously_found_devices != found_devices:
                logger().info(f"BLE scan results :{found_devices}")
                previously_found_devices = found_devices
            if (
            bt_dut_address in found_devices
            and found_devices[bt_dut_address]
            == adv_data):
                return True
        return False
class WifiSockthread(ThreadBase):

    def __init__(self, remote_socket=None, wifi_dut=None, \
                 wifi_access_point=None, devic_ip=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.device_ip = devic_ip
        self.remote_socket = remote_socket

    def run(self):
        no_of_iterations = 5
        self.remote_socket.interfaces.socket.time_limit = 3600

        logger().info("Starting tcp server remotely at port number 5001")
        self.remote_socket.interfaces.socket.start_server()

        # DUT opens tcp client socket
        sock = self.wifi_dut.interfaces.wifi.open_tcp_client_socket()
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        self.wifi_dut.interfaces.wifi.bind(sock, self.device_ip, local_port)
        # tcp socket opened in DUT connects to the tcp server
        self.wifi_dut.interfaces.wifi.connect_to_server(sock, self.remote_socket.interfaces.socket)
        for i in range(1, no_of_iterations):
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            data_length = len(data_sent)
            self.wifi_dut.interfaces.wifi.send_data(sock, data_length, data=data_sent)
            data_receive = self.remote_socket.interfaces.socket.recv_data_tcp(data_length)
            logger().info(f"data received is {data_receive}")
            time.sleep(55)
        time.sleep(10)
        result = self.wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket"
        self.remote_socket.interfaces.socket.socket_close_indication(1)


class power_number_output():
    def __init__(self, power_meter = None, dtim=None):
        super().__init__()
        self.power_meter = power_meter

    def __print_throughput(self, throughput: dict):
        if throughput is not None:
            print_dict("##     ", throughput)

    def get_power_value(self):
        logger().info("initiating power meter")
        self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log")
        # Init power meter module

        self.power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
        # set power meter out put channels
        logger().info("setting output channels")
        self.power_meter.interfaces.power_meter.set_output_channels_settings(
            [{"channel": "1", "emulation_mode": "Current Measure", "trace_current": True, "trace_voltage": False,
              "trace_power": False}])
        # start capture power meter datalog/scope
        logger().info("starting power meter capture")
        self.power_meter.interfaces.power_meter.start_capture()

        # Parse result as throughput object
        logger().info("parsing output result")
        parsed_result = self.power_meter.interfaces.power_meter.power_meter_module.process_output(
            self.power_meter.interfaces.power_meter.results)
        self.__print_throughput(parsed_result)
        assert parsed_result["Output"] is not None

################coex data transfer case##########

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "set_send_feature_frame": True,
        "rf_type":1,
        "features_enable":49,
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'siddhu11',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv","wifi_powersave_disable", "disassociated"])
def test_wlan_ble_advertise_tx_55sec_data_transfer_C133654(wifi_dut, wifi_access_point, remote_socket, ble_client, power_meter,net_perf_client, protocol, dtim,rs_helper,
                                                  utf_constants):
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"./test_ble_advertise_connectable_power_{int(time.time())}.log",
    ) as bt_logs:
        bcast_in_tim_next_cmd = 1
        beacon_drop = 5000
        bcast_in_tim = 1

        logger().info("Initializing BLE")
        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        logger().info(f'bt_dut adress is" : {bt_dut_address}')

        logger().info("Advertising DUT ")

        logger().info("keeping the DUT in undirected_connectable ADV mode")

        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2056, ble_adv_int_max=2056, ble_adv_channel_map=7)

        logger().info(f"configuring access point with dtim:{dtim}")
        wifi_access_point.interfaces.wifi.start_ap(dtim=dtim)
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=False)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        logger().info("sending filter broadcast command")
        wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)

        logger().info("Enabling power save")
        wifi_dut.interfaces.wifi.power_save(2, 0)
        wifi_dut.interfaces.wifi.bt_power_save(2, 0)

        time.sleep(20)
        wifi_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut,
                                  wifi_access_point=wifi_access_point, devic_ip=device_ip)
        logger().info("tcp send data thread started ")
        wifi_obj.start()

        logger().info("power meter initiated")
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()


######Connection test case#####
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
                               RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "set_send_feature_frame": True,
    },
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "disassociated"])
def test_wlan_ble_coex_data_trasfer_DTIM10_BLE_connect_200ms_C133655(wifi_dut, wifi_access_point, ble_client, power_meter, dtim,
                                                       rs_helper, utf_constants,net_perf_client,protocol, remote_socket ):
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"./test_ble_advertise_connectable_power_{int(time.time())}.log",
    ) as bt_logs:
        bcast_in_tim_next_cmd = 1
        beacon_drop = 5000
        bcast_in_tim = 1
        logger().info("Initializing BLE")

        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

        logger().info("Advertising DUT ")

        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2056, ble_adv_int_max=2056,
                                                       ble_adv_channel_map=7)
        logger().info("Initiating scan from remote device")

        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
        )
        assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"
        scan_result = device_scan_result()

        device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                        bt_dut_address=bt_dut_address,
                                                                        adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)

        if device_found:
            logger().info("Dut found in scan results")

        logger().info("initiating stop scanning")
        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "DUT not found in scan results"

        logger().info("Initiating connection from remote device")

        ble_client.interfaces.bluetooth.connect(bt_dut_address, min_conn_interval=0xa0,
                                                max_conn_interval=0xa0, conn_latency=0,
                                                supervision_timeout=3200)
        logger().info("Initiating power save")

        logger().info(f"configuring access point with dtim:{dtim}")
        wifi_access_point.interfaces.wifi.start_ap(dtim=dtim)

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=False)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        logger().info("sending filter broadcast command")
        wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)

        logger().info("Enabling power save")
        wifi_dut.interfaces.wifi.power_save(2, 0)
        wifi_dut.interfaces.wifi.bt_power_save(2, 0)
        time.sleep(20)
        wifi_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut,
                                  wifi_access_point=wifi_access_point, devic_ip=device_ip)
        logger().info("tcp send data thread started ")
        wifi_obj.start()
        logger().info("power meter initiated")
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()
        logger().info("Initiating disconnection from remote device")
        ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)