import time
import pytest
import os
from utf.utf_config import UtfConfig

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

def logger():
    return get_logger(__name__)


def power_measurement(power_device=None, power_meter=None, dtim=None):
    if power_device == "keysight_benchvue_power_analyzer_win_wcf":
        power_obj = power_number_output(power_meter=power_meter, dtim=dtim)
    elif power_device == "nrf_ppk2_device":
        power_obj = ppk_power_number_output(power_meter=power_meter)
    power_obj.get_power_value()


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


class ppk_power_number_output():
    def __init__(self, power_meter=None):
        super().__init__()
        self.power_meter = power_meter

    def __print_throughput(self, throughput: dict):
        if throughput is not None:
            print_dict("##     ", throughput)

    def get_power_value(self):

        # Start Capture
        logger().info("Starting PPK capture")
        self.power_meter.interfaces.power_meter.start_capture()
        # Process Output
        file_size = os.path.getsize(self.power_meter.interfaces.power_meter.capture_file)
        assert file_size > 0
        parsed_result = self.power_meter.interfaces.power_meter.process_output()
        self.__print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        time.sleep(10)


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
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv","wifi_powersave_disable", "disassociated"])
def test_wlan_ble_coex_DTIM10_BLE_adv_1_28_C20564(power_meter, wifi_dut, wifi_access_point, ble_client, dtim, rs_helper,
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
        
        logger().info(f"Starting Power Capture")
        power_device = UtfConfig.instance().defaults.get("power_meter", {})
        power_measurement(power_device=power_device, power_meter=power_meter, dtim=dtim)
        time.sleep(15)


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
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "disassociated"])
def test_wlan_ble_coex_DTIM10_BLE_connect_200ms_C20565(power_meter, wifi_dut, wifi_access_point, ble_client, dtim,
                                                       rs_helper, utf_constants):
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
        time.sleep(10)

        logger().info(f"Starting Power Capture")
        power_device = UtfConfig.instance().defaults.get("power_meter", {})
        power_measurement(power_device=power_device, power_meter=power_meter, dtim=dtim)
        time.sleep(15)

        logger().info("Initiating disconnection from remote device")
        ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)


######Connection test case#####
        

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client| RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
                               RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem"],
        "set_tx_wait_time": True,
    },
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets","disassociated"])
def test_wlan_ble_coex_DTIM10_BLE_SSL_connect_200ms_C20557(power_meter, wifi_dut, wifi_access_point, ssl_server, ble_client, utf_constants, rs_helper,dtim):
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"./test_ble_advertise_connectable_power_{int(time.time())}.log",
    ) as bt_logs:
        bcast_in_tim_next_cmd = 1
        beacon_drop = 5000
        bcast_in_tim = 1
        port1 = ssl_server.interfaces.ssl.config['device_port1']
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
                                                supervision_timeout=32000)
        
        logger().info(f"configuring access point with dtim:{dtim}")
        wifi_access_point.interfaces.wifi.start_ap(dtim=dtim)
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=False, associated=False)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        logger().info("sending filter broadcast command")
        wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)

        logger().info("Enabling power save")
        wifi_dut.interfaces.wifi.power_save(2, 0)
        wifi_dut.interfaces.wifi.bt_power_save(2, 0)

        ssl_server.interfaces.ssl.start_server()
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

        time.sleep(10)

        logger().info(f"Starting Power Capture")
        power_device = UtfConfig.instance().defaults.get("power_meter", {})
        power_measurement(power_device=power_device, power_meter=power_meter, dtim=dtim)
        time.sleep(15)

        logger().info("Initiating disconnection from remote device")
        ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)

        ssl_server.interfaces.ssl.stop_server()
        time.sleep(3)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client| RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
                               RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem"],
        "set_tx_wait_time": True,
    },
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets","disassociated"])
def test_wlan_ble_coex_DTIM10_BLE_SSL_connect_200ms_without_traffic_C20566(power_meter, wifi_dut, wifi_access_point, ble_client, utf_constants, rs_helper,dtim):
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
        assert device_found, "dut not found in scan results"
        logger().info(f"Getting Remote BLE characteristics by passing address "
                      f"{wifi_dut.interfaces.wifi.ble_address} from BTmon logs")

        bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

        logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")

        assert (
            "Connectable undirected - ADV_IND (0x00)"
            in bt_logs.device_adv_type
        ),"Expected avd type not found bt mon logs"
        logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
        time.sleep(10)

        logger().info(f"configuring access point with dtim:{dtim}")
        wifi_access_point.interfaces.wifi.start_ap(dtim=dtim)
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=False, associated=False)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        logger().info("sending filter broadcast command")
        wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)

        logger().info("Enabling power save")
        wifi_dut.interfaces.wifi.power_save(2, 0)
        wifi_dut.interfaces.wifi.bt_power_save(2, 0)

        time.sleep(10)
        logger().info(f"Starting Power Capture")
        power_device = UtfConfig.instance().defaults.get("power_meter", {})
        power_measurement(power_device=power_device, power_meter=power_meter, dtim=dtim)
        time.sleep(15)
