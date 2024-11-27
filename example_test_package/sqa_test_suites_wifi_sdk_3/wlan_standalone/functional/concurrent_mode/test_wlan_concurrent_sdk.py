import re
import uuid
from test_apmode_sdk import FilterPacket
from datetime import datetime
import time
from typing import Dict
from random import randint
import test_apmode_sdk as ap
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
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers



"""
    setup requirement:
        1. DUT(RS9117SOC)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
    Test Steps:
        1. Configure the DUT in concurrent mode
        2. create DUT as access point and join DUT to 3rd party access point
        3. Initiate ping from the dut and vice versa
        4.Disconnect dut and connect again
    Author: Jyothi Nagireddy
"""


def logger():
    return get_logger(__name__)


def get_igmp_list(self, dut_mac_address, decryption_key: str, print_layers: list, capture_filename: str) -> Dict[
        str, int]:
        igmp_capture_list = []
        current_time = time.time()
        updated_capture_file = 'filter_' + capture_filename + '_' + str(
            datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
        file_name = f'./reports/{updated_capture_file}.pcap'
        local_capture_file = file_name
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
        packet_filter1 = f'(wlan.addr == {dut_mac_address})'
        self.wifi_sniffer.interfaces.capture.shell(
            f"tshark -nr {self.wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
            f"frame.number -w "
            f"{wlan_filter_file}")
        with self.wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
            sftp.get(wlan_filter_file, local_capture_file)
        for packet in self.wifi_sniffer.interfaces.capture.iter_packets(
                decrypt_packets=True,
                encryption_type="WPA-PWD",
                decryption_key=decryption_key,
                capture_file_filter=local_capture_file
        ):
            for layer in packet.layers:
                layer_name = layer.layer_name.lower()
                if layer_name == "wlan":
                    mac_layer = str(layer)
                    for count in mac_layer.split("\n"):
                        if "Transmitter address" in count:
                            ta_address = count.split(": ")[1].strip()
                if layer_name in print_layers:
                    if ta_address == dut_mac_address:
                        igmp_layer = str(layer)
                        logger().info(f"As per sniffer capture IGMP packets sent by DUT..{ta_address}  ->  {igmp_layer}")
                        igmp_capture_list.append(tuple([igmp_layer, packet.sniff_timestamp]))
                        logger().info(f"*********{igmp_capture_list}")
        return igmp_capture_list


class ConcurrentThread(ThreadBase):
    def __init__(self, wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, net_perf_client=None, protocol=None, testcase_no = None, capture_filename = None,  ping=True, traffic_type=None, stop_sniffer=True, leave=False):
        super().__init__()
        self.ap_mac_address = None
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_clients = wifi_clients
        self.utf_constants = utf_constants
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.testcase_no = testcase_no
        self.capture_filename = capture_filename
        self.ping = ping
        self.traffic_type = traffic_type
        self.stop_sniffer = stop_sniffer
        self.leave = leave
        self.no_of_clients = 1
        self.channel = "11"
        self.ssid = "SILABS_AP_MODE"
        self.security = "WPA2"
        self.password = "Automation@123"
        self.dtim_count = "1"
        self.beacon_interval = "100"

        if self.testcase_no == 19318:
            self.security = "OPEN"

    def run(self):
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        time.sleep(3)
        ping_count = self.utf_constants.get("ping_count")

        self.ipconfig1 = self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")

        self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                            channel=self.channel, ssid=self.ssid,
                                                                            security=self.security,
                                                                            password=self.password,
                                                                            dtim_count=self.dtim_count,
                                                                            beacon_interval=self.beacon_interval,
                                                                            ping_count=ping_count,
                                                                            no_of_clients=self.no_of_clients,
                                                                            leave=self.leave)

        if self.testcase_no == 654504:
            logger().info("***Scanning on AP interface after bringing up DUT in concurrent mode with Specific SSID****")
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid="Concurent_ap", interface="ap")
            logger().info("Scan Results:\n")
            assert len(scan_results) >= 1, " region based probe requests not seen in scan results"

        if self.testcase_no == 654505:
            logger().info("**** Scanning on AP interface after bringing up DUT in concurrent mode with NULL SSID****")
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, interface="ap")
            logger().info("Scan Results:\n")
            assert len(scan_results) >= 1, " region based probe requests not seen in scan results"

        self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut= self.wifi_dut,
                                                       wifi_access_point=self.wifi_access_point,
                                                       power_save=False,
                                                       ping_after_power_save=True, retry_count=3,
                                                       associated=self.wifi_dut.interfaces.wifi.associated
                                                       )

        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {self.ap_mac_address}")

        if self.ping:
            status = ping(self.dut_addr_dict['dut_ip'], 10)
            assert status == 1, "failed to ping to client"

        if self.traffic_type == "Tx":
            logger().info(f"***** starting iperf ******")
            self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.dut_addr_dict['client_ip'],
                                                                 device_ip=self.dut_addr_dict['dut_ip'],
                                                                 protocol=self.protocol)
            self.net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** send traffic  ******")
            self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                local_ip=self.dut_addr_dict['dut_ip'],
                                                remote_ip=self.dut_addr_dict['client_ip'],
                                                remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                size=1460, ttl=30, throughput_type=1, qos=0)
            logger().info(f"***** get and print throughput ******")
            tp = self.net_perf_client.interfaces.net_perf.process_output()
            assert tp, "failed to get throughput..."
            logger().info("data transfer is successful")
        if self.stop_sniffer:
            logger().info("Stop sniffer finally")
            self.wifi_sniffer.interfaces.capture.stop_capture()

    def sta_ap_connection(self):
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        time.sleep(3)
        ping_count = self.utf_constants.get("ping_count")
        self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                            wifi_access_point=self.wifi_access_point,
                                                            power_save=False,
                                                            ping_after_power_save=True, retry_count=3,
                                                            associated=self.wifi_dut.interfaces.wifi.associated
                                                            )
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {self.ap_mac_address}")
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                            channel=self.channel, ssid=self.ssid,
                                                                            security=self.security,
                                                                            password=self.password,
                                                                            dtim_count=self.dtim_count,
                                                                            beacon_interval=self.beacon_interval,
                                                                            ping_count=ping_count,
                                                                            no_of_clients=self.no_of_clients,
                                                                            leave=self.leave)

        if self.traffic_type == "Tx":
            self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                       protocol=self.protocol, device_ip=self.dut_addr_dict['dut_ip'],
                                       host_ip=self.dut_addr_dict['client_ip'], timeout=30, traffic_type="TX")

        # logger().info("Stop sniffer finally")
        # self.wifi_sniffer.interfaces.capture.stop_capture()

    def datatransfer_tx(self):
        logger().info(f"***** starting iperf ******")
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.dut_addr['client_ip'],
                                                             device_ip=self.dut_addr['device_ip'],
                                                             protocol=self.protocol)
        self.net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** send traffic  ******")
        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                            local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            local_ip=self.dut_addr['device_ip'],
                                            remote_ip=self.dut_addr_dict['client_ip'],
                                            remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            size=1460, ttl=30, throughput_type=1, qos=0)
        logger().info(f"***** get and print throughput ******")
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp, "failed to get throughput..."
        logger().info("data transfer is successful")
        time.sleep(5)

    def concurrent_sniffer_validation(self):
        # packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
        #     sa_addr=self.dut_addr_dict['dut_mac_address'],
        #     filter_name='beacon')
        # assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        #     'Unable to find  beacon in Sniffer'
        self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer,
                                                    self.dut_addr['dut_mac_address'],
                                                    self.ap_mac_address, self.sniffer_filter,
                                                    power_save=False)

    def ap_sta_disconnection(self):
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()
        self.wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_concurrent_mode_sta_ap_c19312(wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, protocol, net_perf_client):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, net_perf_client=net_perf_client, protocol=protocol,testcase_no=19312, capture_filename="test_c19312", traffic_type="Tx")
        conc_obj.sta_ap_connection()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()
        conc_obj.ap_sta_disconnection()

    except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_concurrent_mode_sta_ap_c19321(wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, sniffer_filter, multicast_client, utf_constants, sl_collections, protocol, net_perf_client):
    """ To Verify Dut Behaviour  multicast in  STA and AP connection by enabling concurrent mode"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, testcase_no=19312, capture_filename="test_c19321")
        conc_obj.sta_ap_connection()
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"**********{dut_mac_address}***************")
        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address(interface=16)
        logger().info("starting the server from Remote device")
        logger().info(f"starting iperf")
        net_perf_client.interfaces.net_perf.init_server(host_ip=conc_obj.dut_addr_dict['client_ip'],
                                                        device_ip=conc_obj.dut_addr_dict['dut_ip'],
                                                        protocol=protocol, time_out=30, bind_address=multicast_ip)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=conc_obj.dut_addr_dict['dut_ip'], remote_ip=multicast_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1470,
                                       ttl=30,
                                       throughput_type=2, qos=0, async_socket=1)
        logger().info(f"get and print throughput")
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        wifi_dut.interfaces.wifi.sl_net_leave_multicast_address(interface=16)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            filter_name='beacon')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon in Sniffer'
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address,
            filter_name='multicast_concurrent')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  multicast_concurrent in Sniffer'
        conc_obj.concurrent_sniffer_validation()
        conc_obj.ap_sta_disconnection()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_device_as_ap_and_sta_c19313(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                      protocol, net_perf_client, utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour in AP and STA connection by enabling concurrent mode"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, net_perf_client=net_perf_client, protocol=protocol, testcase_no=19312,
                                    capture_filename="test_c19313", ping=True, traffic_type="Tx", stop_sniffer=False)
        conc_obj.start()
        conc_obj.wait_for_exit()
        time.sleep(5)
        conc_obj.ap_sta_disconnection()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
def test_wifi_sdk_device_as_ap_and_sta_c19323(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                      utf_constants, sniffer_filter, remote_socket):
    """ To Verify Dut Behaviour with the 3rd AP connection by enabling concurrent mode"""
    try:
        local_port = randint(5001, 6000)
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, testcase_no=19312,
                                    capture_filename="test_c19314")
        conc_obj.start()
        conc_obj.wait_for_exit()
        remote_socket.interfaces.socket.start_server(port=local_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = remote_socket.interfaces.socket.server_port
        tcp_socket_id = wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
        bind_response = wifi_dut.interfaces.wifi.bind(tcp_socket_id, conc_obj.dut_addr_dict['dut_ip'], 4,
                                                      server_port=server_port, timeout=5)
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
        send_bytes = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data="Thisisfromclient",
                                                            timeout=120)
        logger().info(f'SEND-Bytes = {send_bytes}')
        wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        remote_socket.interfaces.socket.socket_close_indication(1)
        time.sleep(8)
        event_data_output = ""
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.REMOTE_TERMINATE:
                event_data_output = event.event_data
                logger().info(f"*****{event_data_output}*******")
        assert "Remote Terminate" in event_data_output, "expected error code not found. Expected is Remote Terminate"
        logger().info(f" ***************** EVENT DATA IS : {event_data_output} ********************** ")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
def test_wifi_sdk_device_as_ap_and_sta_c19314(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                      utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour  disconnecting the 3rd AP connection by enabling concurrent mode
        To Verify dut reconnection after disconnection"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, testcase_no=19312,
                                    capture_filename="test_c19314")
        conc_obj.start()
        conc_obj.wait_for_exit()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
            logger().info(f"reconnecting  to DUT-AP")
            wifi_clients[i].interfaces.wifi.join()
            dut_ip = wifi_dut.interfaces.wifi.get_device_ip(conc_obj.ipconfig1)
            logger().info(f"********* Dut IP **********: {dut_ip}")
        conc_obj.ap_sta_disconnection()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
def test_wifi_sdk_device_as_ap_and_sta_c19315(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                   utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour by disconnecting the connected STA  by enabling concurrent mode
        To Verify dut reconnection after disconnection"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, testcase_no=19312,
                                    capture_filename="test_c19315")
        conc_obj.start()
        conc_obj.wait_for_exit()
        logger().info("Disconnecting DUT station from 3rd party AP")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            power_save=False,
                                            ping_after_power_save=True, retry_count=3,
                                            associated=wifi_dut.interfaces.wifi.associated
                                            )
        wifi_dut.interfaces.wifi.leave()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "cipher": 'AES', "channel": 11})
def test_wifi_sdk_device_as_ap_and_sta_c19319(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                      utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour when we use the WPA2-AES security in STA and AP connection by enabling concurrent mode"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point, testcase_no=19312,
                                    capture_filename="test_c19319")
        conc_obj.start()
        conc_obj.wait_for_exit()
        conc_obj.ap_sta_disconnection()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_device_as_ap_and_sta_c19320(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                      protocol, net_perf_client, utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    """Data transfer between WSC AP and connected STA and between WSC STA and connected AP"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point, net_perf_client=net_perf_client, protocol=protocol,
                                    testcase_no=19312,
                                    capture_filename="test_c19320", ping=True, stop_sniffer=True)
        conc_obj.start()
        conc_obj.wait_for_exit()
        sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client,
                                   protocol=protocol, device_ip=conc_obj.dut_addr_dict['dut_ip'],
                                   host_ip=conc_obj.dut_addr_dict['client_ip'], timeout=40, traffic_type="TX")
        sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client,
                                        protocol=protocol, device_ip=conc_obj.dut_addr_dict['client_ip'],
                                        host_ip=conc_obj.dut_addr_dict['dut_ip'], timeout=40, traffic_type="TX")
        conc_obj.sta_ap_connection()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
def test_wifi_sdk_device_as_ap_and_sta_c19324(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                     utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour in Ap and STA connection by enabling concurrent mode"""
    """To Verify the dut behaviour after multiple disconnection and connection"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point,
                                    testcase_no=19312,
                                    capture_filename="test_c19324")
        conc_obj.start()
        conc_obj.wait_for_exit()
        logger().info("connect and disconnect for multiple times")
        for count in range(1, 4):
            wifi_dut.interfaces.wifi.leave()
            sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                wifi_access_point=wifi_access_point,
                                                power_save=False,
                                                ping_after_power_save=True, retry_count=3,
                                                associated=wifi_dut.interfaces.wifi.associated
                                                )
            logger().info(f'connected and disconnected for {count}nd time')
        conc_obj.ap_sta_disconnection()
        conc_obj.concurrent_sniffer_validation()


    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |  Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "OPEN", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
def test_wifi_sdk_device_as_ap_and_sta_c19317(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                     utf_constants, sniffer_filter, switch):
    """ To Verify Dut rejoin Behaviour in  Ap and STA connection by enabling concurrent mode"""
    try:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=10,
                                                                      scan_interval=4,
                                                                      beacon_missed_count=40,
                                                                      first_time_retry_enable=0)
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point,
                                    testcase_no=19312,
                                    capture_filename="test_c19317")
        conc_obj.start()
        conc_obj.wait_for_exit()
        logger().info("\n\nTurning off the AP")
        switch.interfaces.pdu_switch.turn_off(delay=10)
        logger().info("Successfully powered off AP")
        logger().info("Checking for rejoin fail event from dut, this may take some time....")
        sw = Stopwatch()
        rejoin_msg = 0
        while sw.elapsed_sec <= 500:
            events = wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT:
                    rejoin_msg = 1
            if rejoin_msg:
                break
        assert rejoin_msg == 1, f"Rejoin Error not found from DUT even after AP is switched off for 500 seconds"
        logger().info("Rejoin Error Received from DUT")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("\n\nAgain turning on the AP")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        logger().info("Successfully powered on AP")
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "OPEN", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)

@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
                "ssid": "SILABS_AP_MODE",
                "channel": 11,
                "interface": "wlan0",
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_device_as_ap_and_sta_c19318(sl_collections, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      protocol, net_perf_client, utf_constants, sniffer_filter):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode in different security modes"""
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C535823.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="Open", channel=11,
                                          dtim_beacon_count=1,
                                          beacon_interval=100)
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.Open)
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count:10")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       power_save=False,
                                                       ping_after_power_save=True, retry_count=3,
                                                       associated=wifi_dut.interfaces.wifi.associated
                                                       )
        sl_collections.run_traffic(wifi_dut, net_perf_client, protocol, dut_ip,
                                   client_ip, timeout=60,
                                   traffic_type="TX")
        wifi_client.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

# adding a skip marker as it is still in development
@pytest.mark.skip(reason="Test case is still in development")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
               "ssid": "SILABS_AP_MODE",
               "channel": 11,
               "interface": "wlan0",
         }
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_device_as_ap_and_sta_concurrent_mode_C148577(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, protocol, net_perf_client, utf_constants, sniffer_filter):
    """Test Case Description:
        1. Start sniffer capture on the configured AP channel.
        2. Configure the module in concurrent mode and check for successful initialization.
        3. Run the SSL server using the specified command.
        4. Connect to the access point and verify successful authentication and association.
        5. Configure the DUT to obtain an IP address via DHCP.
        6. Start the access point and confirm it sends beacons and accepts connections from other stations.
        7. Connect and disconnect 2nd and 3rd party stations to the access point without issues.
        8. Load the SSL CA certificate.
        9. Create a socket for SSL communication.
        10. Bind the socket to an address.
        11. Connect the socket to the SSL server.
        12. Send data through the socket and confirm the number of bytes sent.
        13. Close the client socket.
        14. Disconnect from the access point.
        15. Stop the sniffer.
        16. Repeat steps 4 to 14.
    """
    try:
        # Step 1: Start sniffer capture
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_concurrent_mode.pcap")
        time.sleep(3)

        # Step 2: Configure the module in concurrent mode
        wifi_dut.interfaces.wifi.configure_mode(Si91xOperatingMode.ConcurrentMode)
        assert wifi_dut.interfaces.wifi.is_mode_configured(Si91xOperatingMode.ConcurrentMode), "Failed to configure concurrent mode"

        # Step 3: Run the SSL server
        ssl_server_command = "start_ssl_server_command"
        sl_collections.run_command(ssl_server_command)

        # Step 4: Connect to the access point
        wifi_dut.interfaces.wifi.join(ssid="Concurent_ap", security=SecurityMode.WPA2, passphrase="test1234")
        assert wifi_dut.interfaces.wifi.is_connected(), "Failed to connect to the access point"

        # Step 5: Configure the DUT to obtain an IP address via DHCP
        wifi_dut.interfaces.wifi.obtain_ip_via_dhcp()
        dut_ip = wifi_dut.interfaces.wifi.get_ip_address()
        assert dut_ip, "Failed to obtain IP address via DHCP"

        # Step 6: Start the access point
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", channel=11)
        assert wifi_dut.interfaces.wifi.is_ap_started(), "Failed to start the access point"

        # Step 7: Connect and disconnect 2nd and 3rd party stations
        for _ in range(2):
            wifi_clients.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2, passphrase="Automation@123")
            time.sleep(5)
            wifi_clients.interfaces.wifi.leave()
            time.sleep(5)

        # Step 8: Load the SSL CA certificate
        wifi_dut.interfaces.ssl.load_ca_certificate("path_to_ca_certificate")

        # Step 9: Create a socket for SSL communication
        ssl_socket = wifi_dut.interfaces.ssl.create_socket()

        # Step 10: Bind the socket to an address
        wifi_dut.interfaces.ssl.bind_socket(ssl_socket, dut_ip, 443)

        # Step 11: Connect the socket to the SSL server
        wifi_dut.interfaces.ssl.connect_socket(ssl_socket, "ssl_server_ip", 443)

        # Step 12: Send data through the socket
        bytes_sent = wifi_dut.interfaces.ssl.send_data(ssl_socket, "Test data")
        assert bytes_sent > 0, "Failed to send data through the socket"

        # Step 13: Close the client socket
        wifi_dut.interfaces.ssl.close_socket(ssl_socket)

        # Step 14: Disconnect from the access point
        wifi_dut.interfaces.wifi.leave()

        # Step 15: Stop the sniffer
        wifi_sniffer.interfaces.capture.stop_capture()

        # Step 16: Repeat steps 4 to 14
        for _ in range(2):
            wifi_dut.interfaces.wifi.join(ssid="Concurent_ap", security=SecurityMode.WPA2, passphrase="test1234")
            wifi_dut.interfaces.wifi.obtain_ip_via_dhcp()
            wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", channel=11)
            wifi_clients.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2, passphrase="Automation@123")
            wifi_clients.interfaces.wifi.leave()
            wifi_dut.interfaces.ssl.load_ca_certificate("path_to_ca_certificate")
            ssl_socket = wifi_dut.interfaces.ssl.create_socket()
            wifi_dut.interfaces.ssl.bind_socket(ssl_socket, dut_ip, 443)
            wifi_dut.interfaces.ssl.connect_socket(ssl_socket, "ssl_server_ip", 443)
            wifi_dut.interfaces.ssl.send_data(ssl_socket, "Test data")
            wifi_dut.interfaces.ssl.close_socket(ssl_socket)
            wifi_dut.interfaces.wifi.leave()
            wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        wifi_sniffer.interfaces.capture.stop_capture()

# adding a skip marker as it is still in development
@pytest.mark.skip(reason="Test case is still in development")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
               "ssid": "SILABS_AP_MODE",
               "channel": 11,
               "interface": "wlan0",
         }
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_concurrent_mode_https_download_C148584(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, protocol, net_perf_client, utf_constants, sniffer_filter):
    """Test Case Description:
    1. Configure the module in concurrent mode and check for successful initialization.
    2. Start the HTTPS server on AP B and ensure it runs without issues.
    3. Start the access point and confirm successful initialization.
    4. Connect to the access point and verify successful authentication and association.
    5. Configure the DUT to obtain an IP address via DHCP.
    6. Initiate an HTTPS download from the server and ensure it succeeds.
    7. Attempt to connect to the access point from a 3rd party remote device with an incorrect PSK, and verify the connection fails.
    8. Confirm that the HTTPS file download continues uninterrupted despite the 3rd party connection attempt, with the download remaining successful and the association failing.
    """
    try:
        # Step 1: Configure the module in concurrent mode
        wifi_dut.interfaces.wifi.configure_mode(Si91xOperatingMode.ConcurrentMode)
        assert wifi_dut.interfaces.wifi.is_mode_configured(Si91xOperatingMode.ConcurrentMode), "Failed to configure concurrent mode"

        # Step 2: Start the HTTPS server on AP B
        https_server_command = "start_https_server_command"
        sl_collections.run_command(https_server_command)
        assert sl_collections.is_https_server_running(), "Failed to start HTTPS server"

        # Step 3: Start the access point
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", channel=11)
        assert wifi_dut.interfaces.wifi.is_ap_started(), "Failed to start the access point"

        # Step 4: Connect to the access point
        wifi_dut.interfaces.wifi.join(ssid="Concurent_ap", security=SecurityMode.WPA2, passphrase="test1234")
        assert wifi_dut.interfaces.wifi.is_connected(), "Failed to connect to the access point"

        # Step 5: Configure the DUT to obtain an IP address via DHCP
        wifi_dut.interfaces.wifi.obtain_ip_via_dhcp()
        dut_ip = wifi_dut.interfaces.wifi.get_ip_address()
        assert dut_ip, "Failed to obtain IP address via DHCP"

        # Step 6: Initiate an HTTPS download from the server
        download_command = "https_download_command"
        sl_collections.run_command(download_command)
        assert sl_collections.is_download_successful(), "Failed to download file via HTTPS"

        # Step 7: Attempt to connect to the access point from a 3rd party remote device with an incorrect PSK
        wifi_clients.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2, passphrase="wrong_passphrase")
        assert not wifi_clients.interfaces.wifi.is_connected(), "3rd party device should not connect with incorrect PSK"

        # Step 8: Confirm that the HTTPS file download continues uninterrupted
        assert sl_collections.is_download_successful(), "HTTPS download was interrupted by 3rd party connection attempt"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        wifi_sniffer.interfaces.capture.stop_capture()


# adding a skip marker as it is still in development
@pytest.mark.skip(reason="Test case is still in development")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
               "ssid": "SILABS_AP_MODE",
               "security": "WPA2",
               "passphrase": "Automation@123",
               "channel": 11
           }
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_concurrent_mode_ssl_communication_C148586(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, protocol, net_perf_client, utf_constants, sniffer_filter):
    """Test Case Description:
    1. Start sniffer capture on the configured AP channel.
    2. Configure the module in concurrent mode and check for successful initialization.
    3. Run the SSL server with the specified command and ensure it starts successfully.
    4. Connect to the access point and verify successful authentication and association.
    5. Configure the DUT to obtain an IP address via DHCP.
    6. Start the access point and confirm successful initialization and beacon transmission.
    7. Connect and disconnect 2nd and 3rd party stations to the access point without issues.
    8. Load the SSL CA certificate.
    9. Create a socket for SSL communication and confirm successful creation.
    10. Bind the socket to an address and check for success.
    11. Connect the socket to the SSL server and verify successful connection.
    12. Send data through the socket and confirm the number of bytes sent.
    13. Close the client socket.
    14. Disconnect from the access point and ensure it succeeds.
    15. Stop the sniffer.
    16. Repeat steps 4 to 14.
    """
    try:
        # Step 1: Start sniffer capture
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_concurrent_mode.pcap")
        time.sleep(3)

        # Step 2: Configure the module in concurrent mode
        wifi_dut.interfaces.wifi.configure_mode(Si91xOperatingMode.ConcurrentMode)
        assert wifi_dut.interfaces.wifi.is_mode_configured(Si91xOperatingMode.ConcurrentMode), "Failed to configure concurrent mode"

        # Step 3: Run the SSL server
        ssl_server_command = "start_ssl_server_command"
        sl_collections.run_command(ssl_server_command)
        assert sl_collections.is_ssl_server_running(), "Failed to start SSL server"

        # Step 4: Connect to the access point
        wifi_dut.interfaces.wifi.join(ssid="Concurent_ap", security=SecurityMode.WPA2, passphrase="test1234")
        assert wifi_dut.interfaces.wifi.is_connected(), "Failed to connect to the access point"

        # Step 5: Configure the DUT to obtain an IP address via DHCP
        wifi_dut.interfaces.wifi.obtain_ip_via_dhcp()
        dut_ip = wifi_dut.interfaces.wifi.get_ip_address()
        assert dut_ip, "Failed to obtain IP address via DHCP"

        # Step 6: Start the access point
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", channel=11)
        assert wifi_dut.interfaces.wifi.is_ap_started(), "Failed to start the access point"

        # Step 7: Connect and disconnect 2nd and 3rd party stations
        for _ in range(2):
            wifi_clients.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2, passphrase="Automation@123")
            assert wifi_clients.interfaces.wifi.is_connected(), "Failed to connect 2nd/3rd party station"
            wifi_clients.interfaces.wifi.leave()
            assert not wifi_clients.interfaces.wifi.is_connected(), "Failed to disconnect 2nd/3rd party station"

        # Step 8: Load the SSL CA certificate
        wifi_dut.interfaces.ssl.load_ca_certificate("path_to_ca_certificate")

        # Step 9: Create a socket for SSL communication
        ssl_socket = wifi_dut.interfaces.ssl.create_socket()
        assert ssl_socket, "Failed to create SSL socket"

        # Step 10: Bind the socket to an address
        wifi_dut.interfaces.ssl.bind_socket(ssl_socket, dut_ip, 443)
        assert wifi_dut.interfaces.ssl.is_socket_bound(ssl_socket), "Failed to bind SSL socket"

        # Step 11: Connect the socket to the SSL server
        wifi_dut.interfaces.ssl.connect_socket(ssl_socket, "ssl_server_ip", 443)
        assert wifi_dut.interfaces.ssl.is_socket_connected(ssl_socket), "Failed to connect SSL socket to server"

        # Step 12: Send data through the socket
        bytes_sent = wifi_dut.interfaces.ssl.send_data(ssl_socket, "Test data")
        assert bytes_sent > 0, "Failed to send data through the socket"

        # Step 13: Close the client socket
        wifi_dut.interfaces.ssl.close_socket(ssl_socket)

        # Step 14: Disconnect from the access point
        wifi_dut.interfaces.wifi.leave()
        assert not wifi_dut.interfaces.wifi.is_connected(), "Failed to disconnect from the access point"

        # Step 15: Stop the sniffer
        wifi_sniffer.interfaces.capture.stop_capture()

        # Step 16: Repeat steps 4 to 14
        for _ in range(2):
            wifi_dut.interfaces.wifi.join(ssid="Concurent_ap", security=SecurityMode.WPA2, passphrase="test1234")
            assert wifi_dut.interfaces.wifi.is_connected(), "Failed to connect to the access point"
            wifi_dut.interfaces.wifi.obtain_ip_via_dhcp()
            dut_ip = wifi_dut.interfaces.wifi.get_ip_address()
            assert dut_ip, "Failed to obtain IP address via DHCP"
            wifi_dut.interfaces.ssl.bind_socket(ssl_socket, dut_ip, 443)
            wifi_dut.interfaces.ssl.connect_socket(ssl_socket, "ssl_server_ip", 443)
            bytes_sent = wifi_dut.interfaces.ssl.send_data(ssl_socket, "Test data")
            assert bytes_sent > 0, "Failed to send data through the socket"
            wifi_dut.interfaces.ssl.close_socket(ssl_socket)
            wifi_dut.interfaces.wifi.leave()
            assert not wifi_dut.interfaces.wifi.is_connected(), "Failed to disconnect from the access point"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.config(
    "wifi_dut",
    wifi={
         "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
def test_wifi_sdk_concurrent_mode_sta_ap_c535823(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections):
    try:
        packet_filter2 = "    Type/Subtype: Beacon (0x0008)"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C535823.pcap")
        time.sleep(3)
        ping_count = utf_constants.get("ping_count")
        dut_addr =sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                                 wifi_access_point=wifi_access_point,
                                                                 power_save=False,
                                                                 ping_after_power_save=True, retry_count=3,
                                                                 associated=wifi_dut.interfaces.wifi.associated
                                                                 )
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count=1,
                                          beacon_interval=100)
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security="WPA2", passphrase="Automation@123",
                                         scan_ssid=1)
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count:10")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(
            f"DUT MAC ADDRESS :  {dut_mac_address}")
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        logger().info(f'RASPI-STA Disconnecting from DUT-AP')
        wifi_client.interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2), "not found beacon from DUT "
        IE_obj = FilterPacket(open_file=True)
        ssid = IE_obj.get_hidden_ssid()
        logger().info(f"*******{ssid}*********")
        hidden_ssid = 0
        if "Wildcard SSID" in ssid:
            logger().info(f"found the hidden ssid")
            hidden_ssid = 1
        assert hidden_ssid

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
         "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
def test_wifi_sdk_concurrent_mode_sta_ap_c535104(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections):
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C535104.pcap")
        time.sleep(3)
        mac_address_format = ("^([0-9A-Fa-f]{2}[:-])" +
                              "{5}([0-9A-Fa-f]{2})|" +
                              "([0-9a-fA-F]{4}\\." +
                              "[0-9a-fA-F]{4}\\." +
                              "[0-9a-fA-F]{4})$")
        logger().info(f"....Scanning for AP nearby.....")
        wifi_dut.interfaces.wifi.scan(channel=11, ssid=None)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      security=wifi_access_point.interfaces.wifi.security.name.lower(),
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      channel=wifi_access_point.interfaces.wifi.channel,
                                      pmk_enable=False,
                                      enc="ccmp",
                                      expected_negative_status=None,
                                      timeout=60)
        logger().info("....DUT configures the IP Address....")
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30, ip_version='ipv4')
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f'DUT IP : {device_ip}')
        logger().info("....Pinging to DUT.....")
        status = ping(device_ip, 10)
        assert status, "DUT ISN'T RESPONDING FOR PING REQUEST......"
        logger().info("PING TO DUT IS SUCCESSFULLY DONE....")
        STA_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        Compare_str = re.compile(mac_address_format)
        if (re.search(Compare_str, STA_mac_address)):
            client_dut_mac_format = True
        else:
            client_dut_mac_format = False
        assert client_dut_mac_format, f"unable to match mac address"
        logger().info(f"**********Client_mac_address: {STA_mac_address}************")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count=1,
                                          beacon_interval=100)
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security="WPA2", passphrase="Automation@123")
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count:10")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        Ap_interface_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        Compare_str = re.compile(mac_address_format)
        if (re.search(Compare_str, Ap_interface_mac_address)):
            ap_dut_mac_format = True
        else:
            ap_dut_mac_format = False
        assert ap_dut_mac_format, f"unable to match ap interface mac address formate"
        logger().info(
            f"AP INTERFACE MAC ADDRESS :  {Ap_interface_mac_address}")
        logger().info(f'RASPI-STA Disconnecting from DUT-AP')
        wifi_client.interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
         "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
def test_wifi_sdk_concurrent_mode_read_mac_c537336(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections):
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C535104.pcap")
        time.sleep(3)
        sta_mac = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"STA-UT MAC Address: {sta_mac}")
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            power_save=False, ping_after_power_save=False)
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count=1,
                                          beacon_interval=100)
        time.sleep(2)
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"AP-UT MAC Address: {ap_mac}")
        time.sleep(2)
        wifi_client.interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_device_as_ap_and_sta_c477524(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                      utf_constants, sniffer_filter, net_perf_client, protocol):
    """Enable the module to act as 802.11n supported AP, the default HT Capabilities should show the support only for
    20Mhz & the supported data rate should be  72.2 Mbps"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point, net_perf_client=net_perf_client, protocol=protocol, testcase_no=477524,
                                    capture_filename="test_C477524", ping=True, traffic_type="Tx", stop_sniffer=True, htcaps=1)
        conc_obj.start()
        conc_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=conc_obj.dut_addr_dict['dut_mac_address'],
            filter_name="beacon_ht")
        logger().info(f"packet_filter1: {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: Unable to find htcaps_IES packet in sniffer'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
         "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
            "ssid": "SILABS_AP_MODE",
            "channel": 11,
            "interface": "wlan0",
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
def test_wifi_sdk_concurrent_mode_sta_ap_c586187(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,sl_collections):
    """Check the 3rd party STA Association to APUT(OPEN security) with Hidden SSID Mode in Concurrent Mode"""
    try:
        packet_filter2 = "    Type/Subtype: Beacon (0x0008)"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C535823.pcap")
        time.sleep(3)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                                 wifi_access_point=wifi_access_point,
                                                                 power_save=False,
                                                                 ping_after_power_save=True, retry_count=3,
                                                                 associated=wifi_dut.interfaces.wifi.associated
                                                                 )
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="OPEN", channel=11,
                                          dtim_beacon_count=1,
                                          beacon_interval=100)
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.Open,
                                         scan_ssid=1)
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count:10")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(
            f"DUT MAC ADDRESS :  {dut_mac_address}")
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        logger().info(f'RASPI-STA Disconnecting from DUT-AP')
        wifi_client.interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2), "not found beacon from DUT "
        IE_obj = FilterPacket(open_file=True)
        ssid = IE_obj.get_hidden_ssid()
        logger().info(f"*******{ssid}*********")
        hidden_ssid = 0
        if "Wildcard SSID" in ssid:
            logger().info(f"found the hidden ssid")
            hidden_ssid = 1
        assert hidden_ssid

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
def test_wifi_sdk_concurrent_mode_sta_ap_scan_c563958(wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                                      sniffer_filter,sl_collections, utf_constants):
    """Verification of bgscan/advanced scan functionality STA Interface after AP Start in Concurrent Mode """
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point, testcase_no=563958, capture_filename="test_c563958")
        conc_obj.sta_ap_connection()

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS :  {dut_mac_address}")
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT AP MAC ADDRESS :  {dut_ap_mac_address}")

        logger().info("**** Scanning on STA interface after bringing up DUT as (STA+AP)****")
        wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                 adv_passive_channel_time=20,
                                                                 adv_enable_multi_probe=1)
        logger().info("\n *** Enable BGscan *** \n")
        wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
        time.sleep(30)

        conc_obj.ap_sta_disconnection()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address,
            filter_name="probe_request")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon and probe request broadcast packet'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
def test_wifi_sdk_concurrent_mode_sta_ap_scan_c563959(wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                                      sniffer_filter, utf_constants, sl_collections):
    """ Verify the bgscan/advanced scan functionality of STA interface after AP interface down """
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point, testcase_no=563959, capture_filename="test_c563959")
        conc_obj.sta_ap_connection()

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS :  {dut_mac_address}")
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT AP MAC ADDRESS :  {dut_ap_mac_address}")

        logger().info(f"Stop the AP ")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        logger().info("**** Scanning on STA interface after bringing down AP interface****")
        wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                 adv_passive_channel_time=20,
                                                                 adv_enable_multi_probe=1)
        logger().info("\n *** Enable BGscan *** \n")
        wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
        time.sleep(30)

        conc_obj.ap_sta_disconnection()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address,
            filter_name="probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon and probe request broadcast packet'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
def test_wifi_sdk_concurrent_mode_ap_sta_scan_c654504(wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                                      sniffer_filter, sl_collections, utf_constants):
    """ Verify scan functionality after configuring our device as first AP and next STA with Specific SSID in
        Concurrent Mode  scan """
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point, stop_sniffer=True, testcase_no=654504, capture_filename="test_c654504")
        conc_obj.start()
        conc_obj.wait_for_exit()

        time.sleep(5)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS :  {dut_mac_address}")
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT AP MAC ADDRESS :  {dut_ap_mac_address}")

        conc_obj.ap_sta_disconnection()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address,
            filter_name="probe_request")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon and probe request broadcast packet'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
def test_wifi_sdk_concurrent_mode__ap_sta_scan_c654505(wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                                       sniffer_filter, sl_collections,utf_constants):
    """ Verify scan functionality after configuring our device as first AP and next STA with NULL SSID in
        Concurrent Mode  scan """
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter,  wifi_clients,
                                    utf_constants, wifi_access_point, stop_sniffer=True, testcase_no=654505, capture_filename="test_c654505")
        conc_obj.start()
        conc_obj.wait_for_exit()

        time.sleep(5)

        conc_obj.ap_sta_disconnection()

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS :  {dut_mac_address}")
        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT AP MAC ADDRESS :  {dut_ap_mac_address}")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address,
            filter_name="probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon and probe request broadcast packet'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
def test_wifi_sdk_concurrent_mode_sta_ap_scan_c654506(wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                                      sniffer_filter, sl_collections, utf_constants):
    """ Negative:Verify scan functionality after configuring our device as first STA and next AP with SSID as NULL in
        Concurrent Mode  scan should fail with 1002 error"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients,
                                    utf_constants, wifi_access_point, stop_sniffer=True, testcase_no=654506,
                                    capture_filename="test_c654506")
        conc_obj.sta_ap_connection()

        logger().info("******** Scanning on AP interfaces after bringing up DUT as (STA+AP) *********")
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, interface="ap")
            logger().info(f"error code received:{exc_info.value.error_code}")
        assert exc_info.value.error_code == 0x10002, "Did not receive the desired error code from DUT, failing the test"
        logger().info("Found the desired error code 0x10002, which is expected hence marking the test case pass")

    except Exception as Ex:
        if "0x10002" in str(Ex):
            logger().info(f"expected error code: {Ex}")
            logger().info(
                f"Expected error code -->0x10002 -Scan command issued while device is already associated with an ap")
        else:
            raise Ex

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

