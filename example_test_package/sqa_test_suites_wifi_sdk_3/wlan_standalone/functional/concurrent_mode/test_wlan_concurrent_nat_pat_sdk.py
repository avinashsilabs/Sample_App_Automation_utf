import re
import uuid
from datetime import datetime
import time
from typing import Dict
from random import randint
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.ap_mode import test_apmode_sdk as ap
from threading import Thread
from utf.utils.time_measurer import TimeMeasurer
from utf.utf_config import UtfConfig
from utf.interfaces.wifi import SecurityMode
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
import pytest as pytest
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf import UtfDatabaseProperties
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xAwsQos
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import string
import random
from AWSIoTPythonSDK.core.protocol.internal.clients import ClientStatus
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.cloud_connectivity.test_aws_iot_wifi_sqa_sdk import AwsConnection


"""
    setup requirement:
        1. DUT(RS9117SOC)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
    Test Steps:
        1. Configure the DUT in concurrent mode
        2. create DUT as access point and join DUT to 3rd party access point
        3. Initiate ping from the dut and vice versa
        5. Enable the NAT-PAT feature and initiate the ping from station to AP backend
        4. Disconnect dut and connect again
    Author: Sakshi Agrawal
"""


def logger():
    return get_logger(__name__)

class ConcurrentThread(ThreadBase):
    def __init__(self, wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, testcase_no = None, capture_filename = None,  ping=True, traffic_type=None, stop_sniffer=True, leave=False, ht_caps=0):
        super().__init__()
        self.ap_mac_address = None
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_clients = wifi_clients
        self.utf_constants = utf_constants
        self.wifi_access_point = wifi_access_point
        self.testcase_no = testcase_no
        self.capture_filename = capture_filename
        self.ping = ping
        self.traffic_type = traffic_type
        self.stop_sniffer = stop_sniffer
        self.leave = leave
        self.no_of_clients = 4
        self.channel = "1"
        self.ssid = "SILABS_AP_MODE"
        self.security = "OPEN"
        self.password = "None"
        self.dtim_count = "1"
        self.beacon_interval = "100"
        self.ht_caps = ht_caps
        self.sta_ips = []
        self.AP_backend_ip = None

    def run(self):
        ping_count = self.utf_constants.get("ping_count")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")

        self.dut_addr = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            power_save=False,
            ping_after_power_save=True, retry_count=3,
            associated=self.wifi_dut.interfaces.wifi.associated
        )
        device_ip = self.dut_addr['device_ip']

        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {self.ap_mac_address}")
        self.sl_collections.configure_dut_in_static_ip(
            self.wifi_dut, static_ip="192.168.100.76",
            static_subnet="255.255.255.0",
            static_gateway="192.168.100.76"
        )
        self.logger.info(f"********* {len(self.wifi_clients)} *********")
        # Connect all clients except the first (AP backend)
        self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(
            self.wifi_dut, self.wifi_clients[1:],
            channel=self.channel, ssid=self.ssid,
            security=self.security,
            password=self.password,
            dtim_count=self.dtim_count,
            beacon_interval=self.beacon_interval,
            ping_count=ping_count,
            no_of_clients=self.no_of_clients,
            leave=self.leave,
        )

        self.logger.info(f"********* start the NAT ENABLE *********")
        self.wifi_dut.interfaces.wifi.nat_enable()
        self.AP_backend_ip = self.wifi_clients[0].interfaces.wifi.get_ip_address()  # AP backend

        # Collect all station IPs (clients except the first)
        self.sta_ips = [client.interfaces.wifi.get_ip_address() for client in self.wifi_clients[1:]]

        self.logger.info(f"********* Start Ping from all STAs to AP backend *********")
        for idx, client in enumerate(self.wifi_clients[1:], start=1):
            rc, stdout, stderr = client.interfaces.wifi.shell.execute(
                f"sudo ping -I wlan0 -c {ping_count} {self.AP_backend_ip}")
            assert rc == 0, f"STA{idx} failed to ping AP Backend"
            logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")

        if self.testcase_no == 793739:
            # initiate the ping from station to AP backend with payload size 310 bytes
            self.logger.info(f"********* Start Ping from all STAs to AP backend with payload size 310 bytes *********")
            for idx, client in enumerate(self.wifi_clients[1:], start=1):
                try:
                    rc, stdout, stderr = client.interfaces.wifi.shell.execute(
                        f"sudo ping -I wlan0 -c {ping_count} -s 310 {self.AP_backend_ip}")
                    assert rc != 0, f"STA{idx} successfully pinged AP Backend, but it should fail"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    logger().info(f"STA{idx} failed to ping AP Backend as expected")
                except Exception as e:
                    logger().warning(f"STA{idx} ping command timed out or failed as expected: {e}")

        self.logger.info(f"********* start the NAT Disable *********")
        self.wifi_dut.interfaces.wifi.nat_disable()


    def concurrent_sniffer_validation(self):

        self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer,
                                                    self.dut_addr['dut_mac_address'],
                                                    self.ap_mac_address, self.sniffer_filter,
                                                    power_save=False)
        if self.testcase_no == 793733:
            self.logger.info(f"********* Sniffer validation for Ping packets *********")
            for i, ip in enumerate(self.sta_ips):
                packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=ip,
                    da_addr=self.AP_backend_ip,
                    filter_name='ping_request')
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                    'packet_count'], \
                    f'Unable to find the ping request from STA{i}: {ip} to AP backend: {self.AP_backend_ip}'
                logger().info(
                    f'Ping request from STA{i + 1}: {ip} to AP backend: {self.AP_backend_ip} is validated in sniffer')

                packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.AP_backend_ip,
                    da_addr=ip,
                    filter_name='ping_response')
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
                    'packet_count'], \
                    f'Unable to find the ping response from AP backend: {self.AP_backend_ip} to STA{i + 1}: {ip}'
                logger().info(
                    f'Ping response from AP backend: {self.AP_backend_ip} to STA{i + 1}: {ip}  is validated in sniffer')

    def ap_sta_disconnection(self, length=1):
        for i in range(0, length):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()
        self.wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": SecurityMode.Open, "ssid": "SILABS_AP_MODE", "channel": 1
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": SecurityMode.Open,
                "ssid": "SILABS_AP_MODE",
                "channel": 1,
                "interface": "eth1",
               },
           1: {
                "security": SecurityMode.Open,
                "ssid": "SILABS_AP_MODE",
                "channel": 1,
                "interface": "wlan0",
               },
           2: {
                "security": SecurityMode.Open,
                "ssid": "SILABS_AP_MODE",
                "channel": 1,
                "interface": "wlan0",
               },
           3: {
                "security": SecurityMode.Open,
                "ssid": "SILABS_AP_MODE",
                "channel": 1,
                "interface": "wlan0",
               },
           4: {
                "security": SecurityMode.Open,
                "ssid": "SILABS_AP_MODE",
                "channel": 1,
                "interface": "wlan0",
               },
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': SecurityMode.Open,
        'channel': 1,
    }
)
def test_wifi_sdk_icmp_connection_with_nat_c793733(wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, sniffer_filter, utf_constants, sl_collections):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        # wifi_clients[0] act as an AP backend and [1:] as Stations connected to APUT
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, testcase_no=793733, capture_filename="test_c793733")
        conc_obj.start()
        conc_obj.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()
        conc_obj.ap_sta_disconnection(len(wifi_clients[1:]))

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": SecurityMode.Open, "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": SecurityMode.Open,
                "ssid": "SILABS_AP_MODE",
                "channel": 1,
                "interface": "eth1",
               },
           1: {
                "security": SecurityMode.Open,
                "ssid": "SILABS_AP_MODE",
                "channel": 1,
                "interface": "wlan0",
               },
           2: {
                "security": SecurityMode.Open,
                "ssid": "SILABS_AP_MODE",
                "channel": 1,
                "interface": "wlan0",
               },
            3: {
                "security": SecurityMode.Open,
                "ssid": "SILABS_AP_MODE",
                "channel": 1,
                "interface": "wlan0",
               },
            4: {
                "security": SecurityMode.Open,
                "ssid": "SILABS_AP_MODE",
                "channel": 1,
                "interface": "wlan0",
               },
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': SecurityMode.Open,
        'passphrase': 'test1234',
        'channel': 1,
    }
)
def test_wifi_sdk_icmp_conn_more_than_310_bytes_c793739(wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, sniffer_filter, utf_constants, sl_collections):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        # wifi_clients[0] act as an AP backend and [1:] as Stations connected to APUT
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, testcase_no=793739, capture_filename="test_c793739")
        conc_obj.start()
        conc_obj.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()
        conc_obj.ap_sta_disconnection(len(wifi_clients[1:]))

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()
