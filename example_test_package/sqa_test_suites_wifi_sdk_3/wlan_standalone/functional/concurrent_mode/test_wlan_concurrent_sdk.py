import re
import uuid
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.ap_mode.test_apmode_sdk import FilterPacket
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


class APDisconnection(ThreadBase):

    def __init__(self, wifi_dut):
        self.wifi_dut = wifi_dut

    def run(self):
        self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()

class AP_start_STA_connect(ThreadBase):
    """
    This class is responsible for starting AP and connecting STA.
    """

    dut_address = {}

    def __init__(self, wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                 wifi_access_point, net_perf_client=None, protocol=None, testcase_no=None, capture_filename=None,
                 ping=True, traffic_type=None, stop_sniffer=True, leave=False, wifi_client=None):
        super().__init__()
        self.dut_add_dict = {}
        self.dut_addr = {}
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
        self.security = "Open"
        self.password = "Automation@123"
        self.dtim_count = "1"
        self.beacon_interval = "100"
        self.host_ip = None
        self.ping_count = self.utf_constants.get("ping_count")
        self.wifi_client = wifi_client

    def run(self):
        logger().info("... configuring the Sniffer with the channel ...")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        self.wifi_sniffer.interfaces.capture.start_capture(capture_file='test_name')

        AP_start_STA_connect.dut_address = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
            associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
            ping_after_power_save=False, ping_count=self.ping_count)

        self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f".... Remote device ip :{self.host_ip} ....")

        self.wifi_dut.interfaces.wifi.start_ip(
            static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76", vid=1,
            ip_version='ipv4')
        self.dut_add_dict['dut_ap_ipv4'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ap_ipv4']}")

        self.wifi_dut.interfaces.wifi.start_ap(ssid="sharma123", security="WPA2", psk="thisistestnetwork",
                                               channel=11, dtim_beacon_count=1,
                                               beacon_interval=100)

class RunTraffic(AP_start_STA_connect):
    def __init__(self, wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                 wifi_access_point, net_perf_client=None, protocol=None, testcase_no=None, capture_filename=None,
                 ping=True, traffic_type=None, stop_sniffer=True, leave=False):
        super().__init__(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                         wifi_access_point, net_perf_client, protocol, testcase_no, capture_filename, ping,
                         traffic_type, stop_sniffer, leave)

    def run(self):
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
            device_ip=AP_start_STA_connect.dut_address['device_ip'], host_ip=self.host_ip, traffic_type="RX",
            timeout=120)

class HTTPSDownload(AP_start_STA_connect):
    def __init__(self, wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                 wifi_access_point, net_perf_client=None, protocol=None, testcase_no=None, capture_filename=None,
                 ping=True, traffic_type=None, stop_sniffer=True, leave=False, http_server=None, index_path=None):
        super().__init__(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                         wifi_access_point, net_perf_client, protocol, testcase_no, capture_filename, ping,
                         traffic_type, stop_sniffer, leave)
        self.http_server = http_server
        self.index_path = index_path

    def run(self):
        self.sl_collections.http_file_download(wifi_dut=self.wifi_dut, http_server=self.http_server,
                                               device_ip=AP_start_STA_connect.dut_address['device_ip'], index_path=self.index_path, ping_count=10,
                           https=1, server_port=443, retries=1)
class PingFromAPBE(AP_start_STA_connect):

    def run(self):
        self.sl_collections.ping(device_ip=AP_start_STA_connect.dut_address['device_ip'], ping_count=120,
                                 retry_count=3)

class ClientsConnection(AP_start_STA_connect):
    def __init__(self, wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                 wifi_access_point, net_perf_client=None, protocol=None, testcase_no=None, capture_filename=None,
                 ping=True, traffic_type=None, stop_sniffer=True, leave=False):
        super().__init__(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                         wifi_access_point, net_perf_client, protocol, testcase_no, capture_filename, ping,
                         traffic_type, stop_sniffer, leave)

    def run(self):
        for i in range(0, 1):
            connected = False
            self.wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            self.dut_add_dict['dut_ip'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ip']}")
            for count in range(3):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{self.wifi_clients[i].name}' to DUT")
                    self.dut_add_dict['rasp_mac_address'] = self.wifi_clients[i].interfaces.wifi.get_mac_address()
                    logger().info(f"raspi_mac: {self.dut_add_dict['rasp_mac_address']}")
                    self.dut_add_dict['client_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client_ip: {self.dut_add_dict['client_ip']}")
                    rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {self.ping_count} {self.dut_add_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()


class ConcurrentThread(ThreadBase):
    def __init__(self, wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants, wifi_access_point, net_perf_client=None, protocol=None, testcase_no = None, capture_filename = None,  ping=True, traffic_type=None, stop_sniffer=True, leave=False, ht_caps=0):
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
        self.ht_caps = ht_caps

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
                                                                            leave=self.leave, ht_caps=self.ht_caps)

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

    def validate_aws_messages_from_raspi(self):
        logger().info("\n *** Validating received AWS messages ***")
        time.sleep(10)
        # Retrieve received messages from AWS IoT client
        recv_messages = self.aws_iot_client.interfaces.aws_iot.get_received_messages()
        # Validate each received message
        for count in range(5):
            # Log details of the received message
            logger().info(f"Received message {count + 1} is: '{recv_messages[count].payload.decode()}'")
            logger().info(f"Received message {count + 1} topic is: '{recv_messages[count].topic}'")
            logger().info(f"Received message {count + 1} qos is: '{recv_messages[count].qos}'")

    def multi_client_disconnection(self):
        for i in range(0, self.no_of_clients):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()

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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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

        ap_addr = dut_mac_address.split(":")
        try:
            # Safely increment the last part of the MAC address
            last_octet = int(ap_addr[-1], 16) + 1
            ap_addr[-1] = f"{last_octet:02x}"  # Format as two-digit hexadecimal
            dut_ap_mac_addr = ":".join(ap_addr)
            logger().info(f"Updated AP MAC Address: {dut_ap_mac_addr}")
        except (IndexError, ValueError) as e:
            logger.error(f"Error processing MAC address: {dut_mac_address}, {e}")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_ap_mac_addr,
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
        sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                                   device_ip=dut_ip, host_ip=client_ip, timeout=120, traffic_type="TX")
        wifi_client.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": 11,
        },
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma1234", "channel": 11})
@pytest.mark.legacy_deployed
def test_wifi_sdk_AP_STA_UDP_RX_C148577(
        wifi_sniffer, wifi_access_point, wifi_dut, sl_collections, utf_constants, wifi_client,
        wifi_clients, request, protocol, net_perf_client):
    """Verify the Ping functionality of AP and STA in when Assigned with IPv4 address alone in Concurrent Mode
    (STA_First)"""

    try:
        ap_sta_thread = AP_start_STA_connect(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                             wifi_sniffer=wifi_sniffer,
                                             sniffer_filter=None, wifi_clients=wifi_clients,
                                             utf_constants=utf_constants,
                                             wifi_access_point=wifi_access_point, net_perf_client=net_perf_client,
                                             protocol=protocol, testcase_no="C148577", capture_filename=None, ping=True,
                                             traffic_type=None, stop_sniffer=True, leave=False, wifi_client=wifi_client)

        run_traffic_thread = RunTraffic(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_sniffer=wifi_sniffer,
                                        sniffer_filter=None, wifi_clients=wifi_clients, utf_constants=utf_constants,
                                        wifi_access_point=wifi_access_point, net_perf_client=net_perf_client,
                                        protocol=protocol, testcase_no="C148577", capture_filename=None, ping=True,
                                        traffic_type=None, stop_sniffer=True, leave=False)

        client_connection = ClientsConnection(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                              wifi_sniffer=wifi_sniffer,
                                              sniffer_filter=None, wifi_clients=wifi_clients,
                                              utf_constants=utf_constants,
                                              wifi_access_point=wifi_access_point, net_perf_client=net_perf_client,
                                              protocol=protocol, testcase_no="C148577", capture_filename=None,
                                              ping=True,
                                              traffic_type=None, stop_sniffer=True, leave=False)
        ap_sta_thread.start()
        ap_sta_thread.wait_for_exit()
        client_connection.start()
        run_traffic_thread.start()
        client_connection.wait_for_exit()
        run_traffic_thread.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 4095}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "psk": "thisistestnetwork",
            "ssid": "sharma123",
            "channel": 11,
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "psk": "thisistestnetwork", "ssid": "sharma1234", "channel": 11})
# @pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.parametrize("index_path", {"5MB.htm"})
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_HTTPS_download_incorrect_PSK_C148584(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, utf_constants, wifi_client,
        wifi_clients, index_path, http_server ):
    """Verify the HTTPS download functionality of AP and STA in when Assigned with IPv4 address in Concurrent Mode
    (STA_First)"""

    try:
        ap_sta_thread = AP_start_STA_connect(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                             wifi_sniffer=wifi_sniffer,
                                             sniffer_filter=None, wifi_clients=wifi_clients,
                                             utf_constants=utf_constants,
                                             wifi_access_point=wifi_access_point,
                                             testcase_no="C148584", capture_filename=None,
                                             ping=True,
                                             traffic_type=None, stop_sniffer=True, leave=False,
                                             wifi_client=wifi_client)

        https_download = HTTPSDownload(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_sniffer=wifi_sniffer,
                                       sniffer_filter=None, wifi_clients=wifi_clients, utf_constants=utf_constants,
                                       wifi_access_point=wifi_access_point, testcase_no="C148584",
                                       capture_filename=None, ping=True, traffic_type=None,
                                       stop_sniffer=True, leave=False, http_server=http_server, index_path=index_path)

        ap_sta_thread.start()
        ap_sta_thread.wait_for_exit()
        https_download.start()

        for i in range(0, 1):
            wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            try:
                wifi_clients[i].interfaces.wifi.join()
                time.sleep(5)
            except:
                logger().info("This is expected as the PSK is incorrect")

        https_download.wait_for_exit()


    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": 11,
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma1234", "channel": 11})
@pytest.mark.legacy_deployed
def test_wifi_sdk_ping_from_APBE_disable_APUT_C148586(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, utf_constants, wifi_client,
        wifi_clients):
    """Verify the UDP RX functionality of AP and STA in when Assigned with IPv4 address alone in Concurrent Mode
    (STA_First)"""

    try:
        ap_sta_thread = AP_start_STA_connect(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                             wifi_sniffer=wifi_sniffer,
                                             sniffer_filter=None, wifi_clients=wifi_clients,
                                             utf_constants=utf_constants,
                                             wifi_access_point=wifi_access_point,
                                             testcase_no="C148586", capture_filename=None,
                                             ping=True,
                                             traffic_type=None, stop_sniffer=True, leave=False,
                                             wifi_client=wifi_client)

        ping_apbe = PingFromAPBE(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_sniffer=wifi_sniffer,
                                 sniffer_filter=None, wifi_clients=wifi_clients, utf_constants=utf_constants,
                                 wifi_access_point=wifi_access_point,
                                 testcase_no="C148586", capture_filename=None, ping=True,
                                 traffic_type=None, stop_sniffer=True, leave=False)

        ap_disconnect = APDisconnection(wifi_dut=wifi_dut)

        ap_sta_thread.start()
        ap_sta_thread.wait_for_exit()
        ping_apbe.start()
        ap_disconnect.start()
        for i in range(0, 1):
            wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            try:
                wifi_clients[i].interfaces.wifi.join()
                time.sleep(5)
            except:
                logger().info("This is expected as the PSK is incorrect")
        ap_disconnect.wait_for_exit()
        ping_apbe.wait_for_exit()


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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
def test_wifi_sdk_device_as_ap_and_sta_c477524(sl_collections, wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer,
                                      utf_constants, sniffer_filter, net_perf_client, protocol):
    """Enable the module to act as 802.11n supported AP, the default HT Capabilities should show the support only for
    20Mhz & the supported data rate should be  72.2 Mbps"""
    try:
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_clients, utf_constants,
                                    wifi_access_point, net_perf_client=net_perf_client, protocol=protocol, testcase_no=477524,
                                    capture_filename="test_C477524", ping=True, traffic_type="Tx", stop_sniffer=True, ht_caps=1)
        conc_obj.start()
        conc_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=conc_obj.dut_addr_dict['dut_mac_address'],
            filter_name="beacon_HT_capability")
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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
@pytest.mark.legacy_deployed
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


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
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
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.legacy_deployed
def test_wifi_sdk_concurrent_mode_sta_ap_emb_mqtt_c537975(
        wifi_access_point, wifi_dut, wifi_clients, sl_collections, utf_constants, request, wifi_sniffer, sniffer_filter,
        mqtt_server, mqtt_client):
    """ Verify whether DUT is able to subscribe 2 topics with single and multi level wild card and receive the data on 2
     topics in concurrent mode using emb_mqtt"""
    try:
        capture_filename = request.node.name

        topic_wild_first = "mytesttopic/#"
        multiple_topic_first = "mytesttopic/sensor"

        topic_wild_second = "mytesttopic/+/mytesttopic"
        multiple_topic_second = "mytesttopic/automation/mytesttopic"

        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))

        conc_obj = ConcurrentThread(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_clients=wifi_clients,
                                    utf_constants=utf_constants, wifi_access_point=wifi_access_point,
                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                    capture_filename=capture_filename)

        conc_obj.sta_ap_connection()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", server_port=8883, qos=1, is_connection_encrypted=True)

        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(25)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic 1")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild_first, qos=1)

        logger().info("DUT subscribes to the topic 1")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild_first, qos=1)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic 2")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild_second, qos=1)

        logger().info("DUT subscribes to the topic 2")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic_wild_second, qos=1)
        time.sleep(5)

        logger().info("******* MQTT client publishes message over the multiple topics ********")

        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=multiple_topic_first, payload=message, qos=1)
            time.sleep(2)
            mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=multiple_topic_second, payload=message, qos=1)
            time.sleep(2)
            wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()

        logger().info("....Unsubscribing from the topic 1....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic_wild_first)
        time.sleep(3)

        logger().info("....Unsubscribing from the topic 2....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic_wild_second)
        time.sleep(3)

        logger().info("....disconnecting from MQTT broker....")
        wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
        time.sleep(3)

        logger().info("....calling MQTT de-init API....")
        wifi_dut.interfaces.mqtt.mqtt_client_deinit()

        conc_obj.ap_sta_disconnection()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.skip("Test case is failing due to receive message is not working")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"]
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
def test_wifi_sdk_concurrent_mode_sta_ap_aws_mqtt_c537976(
        wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, sniffer_filter, sl_collections, utf_constants, request,
        aws_iot_client):
    """ Verify whether DUT is able to subscribe 2 topics with single and multi level wild card and receive the data on 2
     topics in concurrent mode using aws_mqtt"""
    try:
        capture_filename = request.node.name

        client_id = 'client_c19548'
        topic_wild_first = "mytesttopic/#"
        multiple_topic_first = "mytesttopic/sensor"

        topic_wild_second = "mytesttopic/+/mytesttopic"
        multiple_topic_second = "mytesttopic/automation/mytesttopic"

        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

        conc_obj = ConcurrentThread(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_sniffer=wifi_sniffer,
                                    sniffer_filter=sniffer_filter, wifi_clients=wifi_clients,
                                    utf_constants=utf_constants, wifi_access_point=wifi_access_point,
                                    capture_filename=capture_filename)
        aws_obj = AwsConnection()

        conc_obj.sta_ap_connection()
        logger().info("Initiating aws connect from DUT")
        aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id)
        aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)

        logger().info(f"DUT is Subscribing on topic 1 '{topic_wild_first}' and QOS:'{1}'")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_subscribe(topic_name=topic_wild_first, qos=1)

        logger().info(f"DUT is Subscribing on topic 2 '{topic_wild_second}' and QOS:'{1}'")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_subscribe(topic_name=topic_wild_second, qos=1)

        logger().info(f"AWS IOT Client is Subscribing on topic 1 '{topic_wild_first}' and QOS:'{1}'")
        aws_iot_client.interfaces.aws_iot.received_messages.clear()
        aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(topic_wild_first, qos=1)
        status = aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, f"Subscribe on topic:'{topic_wild_first}' is failed from aws_iot_client"

        logger().info(f"AWS IOT Client is Subscribing on topic 2 '{topic_wild_second}' and QOS:'{1}'")
        aws_iot_client.interfaces.aws_iot.received_messages.clear()
        aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(topic_wild_second, qos=1)
        status = aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, f"Subscribe on topic:'{topic_wild_second}' is failed from aws_iot_client"

        logger().info("******* AWS publishes message over the multiple topics ********")
        aws_obj.publish_from_raspi(aws_iot_client, multiple_topic_first, message, qos=Si91xAwsQos.QOS1)
        time.sleep(3)
        wifi_dut.interfaces.wifi.aws_select_socket()

        logger().info("******* AWS publishes message over the multiple topics ********")
        aws_obj.publish_from_raspi(aws_iot_client, multiple_topic_second, message, qos=Si91xAwsQos.QOS1)
        time.sleep(3)
        wifi_dut.interfaces.wifi.aws_select_socket()

        logger().info("\nValidating received aws message")
        recv_messages = aws_iot_client.interfaces.aws_iot.get_received_messages()
        logger().info(f"Received message is: {recv_messages}")
        logger().info(f"Received message topic is: '{recv_messages.topic}'")
        logger().info(f"Received message qos is: '{recv_messages.qos}'")
        logger().info("aws messages validated successfully")

        logger().info("....Unsubscribing from the topic 1....")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_unsubscribe(topic_name=topic_wild_first)
        time.sleep(2)
        logger().info("....Unsubscribing from the topic 2....")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_unsubscribe(topic_name=topic_wild_second)
        time.sleep(2)
        logger().info("....disconnecting from AWS....")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

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
        },
        1: {
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
@pytest.mark.legacy_deployed
def test_wifi_sdk_concurrent_mode_sta_ap_stability_check_c148587(
        wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, sniffer_filter, sl_collections, utf_constants,
        request):
    """ Verfiy the stability of APUT while disabling the STAUT when pinging between two 3rd party clients associated to
    APUT"""
    try:
        capture_filename = request.node.name

        conc_obj = ConcurrentThread(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_sniffer=wifi_sniffer,
                                    sniffer_filter=sniffer_filter, wifi_clients=wifi_clients,
                                    utf_constants=utf_constants, wifi_access_point=wifi_access_point,
                                    capture_filename=capture_filename)

        conc_obj.no_of_clients = 2
        conc_obj.sta_ap_connection()
        wifi_dut.interfaces.wifi.leave()
        client_first = wifi_clients[0].interfaces.wifi.get_ip_address()
        logger().info(f"IP address of the client 1 is {client_first}")
        client_second = wifi_clients[1].interfaces.wifi.get_ip_address()
        logger().info(f"IP address of the client 2 is {client_second}")
        for i in range(0, 1):
            for count in range(3):
                try:
                    logger().info(f"Initiating client ping from RASPI_STA{i + 1} for ping_count:{10}")
                    rc, stdout, stderr = wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {10} {client_second}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    logger().info(f"RASPI_STA{i + 1} is still connected to DUT-AP")
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.skip("Test case is failing due to http put is not working")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.Default,
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
        },
        1: {
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
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_concurrent_mode_sta_ap_http_put_c148565(
        wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, sniffer_filter, sl_collections, utf_constants, request,
        http_server, index_path):
    """ HTTP Put functionality with exact data buffer size - two clients connected to RSI_AP"""
    try:
        capture_filename = request.node.name

        conc_obj = ConcurrentThread(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_sniffer=wifi_sniffer,
                                    sniffer_filter=sniffer_filter, wifi_clients=wifi_clients, leave=False,
                                    utf_constants=utf_constants, wifi_access_point=wifi_access_point,
                                    capture_filename=capture_filename)
        conc_obj.no_of_clients = 2
        conc_obj.sta_ap_connection()

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init(https_enable=False)

        wifi_dut.interfaces.http.http_put(http_server.interfaces.http, index_path)
        wifi_dut.interfaces.wifi.http_client_deinit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.SL_SI91X_FEAT_LONG_ICMP_PACKET,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "OPEN", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "OPEN",
                "ssid": "SILABS_AP_MODE",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'OPEN',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.deployed_25q2
def test_wifi_sdk_concurrent_mode_large_ping_ipv4_c770037(wifi_access_point, wifi_dut, wifi_clients, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, request):
    ssid = "SILABS_AP_MODE"
    security = "OPEN"
    password = "Automation@123"
    channel = 11
    ping_count = 3
    packet_length = 1472
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        logger().info(" ******* Start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{request.node.name}.pcap")
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                                 wifi_access_point=wifi_access_point,
                                                                 power_save=False,
                                                                 ping_after_power_save=False, retry_count=3,
                                                                 associated=wifi_dut.interfaces.wifi.associated
                                                                 )
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an Access Point ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="OPEN", channel=channel,
                                          dtim_beacon_count=1,
                                          beacon_interval=100)
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP as STA  ********* ")
        wifi_clients[0].interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.Open)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        client_ip = wifi_clients[0].interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        logger().info(f" **** Initiating PING traffic from AP Backend to DUT with 1472 bytes **** ")
        rc, stdout, stderr = wifi_clients[0].interfaces.wifi.shell.execute(
            f"sudo ping -c {ping_count} -s {packet_length} {dut_ip}")
        assert rc == 0, f"\n RASPI-STA failed to ping DUT \n"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        logger().info(f'RASPI-STA Disconnecting from DUT-AP')
        device_ip = wifi_dut.interfaces.wifi.get_ip_address()
        client_ip = wifi_clients[0].interfaces.wifi.get_ip_address()
        icmp_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=client_ip,
            da_addr=device_ip,
            type=8,
            length=1400,
            filter_name='icmpv4_custom_len'
        )
        # Validate that ICMP packets were captured
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=icmp_filter,
                                                           packet_filter2="        Tag: Internet Control Message Protocol")
        with open("./reports/filter2_file.txt", "r") as file:
            data = file.read()
            pattern = r"Data \((\d+) bytes\)"
            match = re.search(pattern, data)
            if match:
                data_length = int(match.group(1))
                logger().info(f"Data length: {data_length} bytes")
            else:
                logger().info("Data length not found.")

        logger().info(f" **** Adding ICMP Header Size: 8 Bytes to Captured Packet Length on-Air, Length: {data_length+8}**** ")
        assert data_length + 8 == 1472, f"\n ICMP Ping Packet Length isn't matching \n"

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_clients[0].interfaces.wifi.leave()

    except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
