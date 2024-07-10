import re
import time
import pytest as pytest
from utf.interfaces.wifi import SecurityMode
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf import UtfDatabaseProperties
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap, Si91xJoinFeatureBitMap,
)
from test_wlan_data_rates_sdk import SocketDataTransfer
from utf_wiseconnect_3.tests.sl_status import SLStatus
from collections import Counter
from utf.interfaces.iperf.iperf_constants import IperfConstants


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Validate MBSSID support in Third party AP's
        4. Scan available ssid's in vicinity and compare with AP configured VAP's list
        5. Connect DUT with T & NT based ssid with different security modes. 
        6. Trigger TCP/UDP traffic suing socket/iperf API's.
        7. Enable rejoin and verify the same functionality with different security modes.
        8. Verify in concurrent modes.

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: Vivek Verma
"""


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None, sniffer_filter=None
                 , ping_count=None, test_name=None, sl_collections=None, net_perf_client=None,
                 wifi_client=None, switch=None, wifi_clients=None, protocol=None, multicast_client=None):
        super().__init__()
        self.scan_list = None
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ping_count = ping_count
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.test_case_no = test_case_no
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.wifi_clients = wifi_clients
        self.protocol = 'TCP'
        self.data = 'Thisisfromclient'
        self.time_period = 60
        self.switch = switch
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        self.ssid = "SILABS_AP_MODE"
        self.security = "WPA2"
        self.password = "Automation@123"
        self.channel = "3"
        self.dtim_count = "1"
        self.beacon_interval = "100"
        self.no_of_clients = 1
        self.protocol = protocol
        self.multicast_client = multicast_client

    def run(self):
        try:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

            if self.test_case_no == 219285:
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()

            elif self.test_case_no == 219286:
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         ping_after_power_save=False)

                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                time.sleep(5)
                self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                                protocol=self.protocol, device_ip=self.dut_addr['device_ip'],
                                                host_ip=host_ip,
                                                timeout=60, traffic_type="TX")

            elif self.test_case_no == 219288:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.wifi_dut.interfaces.wifi.scan()
                time.sleep(60)
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                self.wifi_dut.interfaces.wifi.join(ssid=vap_list[1],
                                                   security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase)

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=False
                                                                         , ping_after_power_save=False, skip_scan=True,
                                                                         skip_connect=True, retry_count=3)

                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                time.sleep(5)

                self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                                protocol=self.protocol, device_ip=self.dut_addr['device_ip'],
                                                host_ip=host_ip,
                                                timeout=60, traffic_type="TX")

            elif self.test_case_no == 219289:
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.
                    MgmtFrameProtectionRequired)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.
                                                                         associated,
                                                                         power_save=True, ping_after_power_save=True)
                logger().info("DUT successfully connected with AP")
                time.sleep(2)
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")

                self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                                protocol=self.protocol, device_ip=self.dut_addr['device_ip'],
                                                host_ip=host_ip,
                                                timeout=60, traffic_type="TX")

            elif self.test_case_no == 219290:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.
                    MgmtFrameProtectionRequired)
                self.wifi_dut.interfaces.wifi.scan()
                self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                   security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=False
                                                                         , ping_after_power_save=False, skip_scan=True,
                                                                         skip_connect=True)

                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")

                self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                                protocol=self.protocol, device_ip=self.dut_addr['device_ip'],
                                                host_ip=host_ip,
                                                timeout=60, traffic_type="TX")

            elif self.test_case_no == 219291:
                for i in range(0, 6):
                    self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                    time.sleep(5)
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                            wifi_access_point=self.wifi_access_point,
                                                                            eap_type='tls',
                                                                            ping_after_power_save=True)

                    self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                    logger().info(f"Remote device ip :{self.host_ip}")
                    time.sleep(5)
                    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = (
                        self.multicast_client.interfaces.multicast.multicast_params())

                    logger().info(f"DUT joining to the multicast group {multicast_ip}")
                    self.wifi_dut.interfaces.wifi.sl_net_join_multicast_address()

                    self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.host_ip, device_ip=multicast_ip, time_out=70,
                                                                    protocol=self.protocol, time_to_leave="32", bandwidth="60M",
                                                                    host_role="C", bind_address=self.host_ip)
                    logger().info(f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}")
                    logger().info(f"***** starting iperf ******")
                    self.net_perf_client.interfaces.net_perf.start()
                    logger().info(f"***** start listening  ******")
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                                   local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                   local_ip=multicast_ip, remote_ip=self.host_ip,
                                                   remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                   size=1470, ttl=60, throughput_type=4, qos=0, async_socket=1, timeout=70)

                    self.wifi_dut.interfaces.wifi.sl_net_leave_multicast_address()
                    logger().info("Stop Sniffer finally")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    self.wifi_dut.interfaces.wifi.leave()
                    time.sleep(5)

            elif self.test_case_no == 219292:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        ssid=vap_list[1],
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type='tls',
                                                                        ping_after_power_save=True, retry_count=3)

                logger().info("DUT successfully connected with AP")
                time.sleep(2)
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol)
                self.net_perf_client.interfaces.net_perf.start()

                self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                     time_period=self.time_period, data=self.data,
                                                     dut_ip=self.dut_addr['device_ip'])
                self.socket_obj.socket_data_transfer()

            elif self.test_case_no == 219293:
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                """ Enabling Rejoin """
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.
                                                                         associated, skip_scan=True,
                                                                         power_save=True, ping_after_power_save=True)
                self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                                protocol=self.protocol, device_ip=self.dut_addr['device_ip'],
                                                host_ip=host_ip,
                                                timeout=60, traffic_type="TX")

            elif self.test_case_no == 219295:
                """ Enabling Rejoin """
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.wifi_dut.interfaces.wifi.scan()
                self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                   security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=False
                                                                         , ping_after_power_save=False, skip_scan=True,
                                                                         skip_connect=True)

                logger().info("DUT successfully connected with AP")
                time.sleep(2)
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")

                self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                                protocol=self.protocol, device_ip=self.dut_addr['device_ip'],
                                                host_ip=host_ip,
                                                timeout=60, traffic_type="TX")

            elif self.test_case_no == 219298:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.wifi_dut.interfaces.wifi.scan()
                self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                   security='open',
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                   expected_status=SLStatus.SL_STATUS_SI91X_REJOIN_FAILURE)

            elif self.test_case_no == 219299:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.wifi_dut.interfaces.wifi.scan()
                status = self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                            security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                            passphrase='1234567899',
                                                            expected_status=
                                                            SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION or
                                                            SLStatus.SL_STATUS_SI91X_REJOIN_FAILURE)

            elif self.test_case_no == 219301:
                for i in range(0, 10):
                    self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                    time.sleep(1)
                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             power_save=False,
                                                                             ping_after_power_save=True, retry_count=3,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated
                                                                             )
                    self.sl_collections.ping(self.dut_addr['device_ip'], ping_count=60)
                    self.wifi_dut.interfaces.wifi.leave()
                    time.sleep(1)

            elif self.test_case_no == 219302:
                # NT BSSID based connection and disconnection multiple times
                for i in range(0, 10):
                    vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                    self.wifi_dut.interfaces.wifi.scan()
                    self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                       security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                       passphrase=self.wifi_access_point.interfaces.wifi.passphrase)
                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=False
                                                                             , ping_after_power_save=True,
                                                                             skip_scan=True,
                                                                             skip_connect=True)
                    self.sl_collections.ping(self.dut_addr['device_ip'], ping_count=60)
                    self.wifi_dut.interfaces.wifi.leave()
                    time.sleep(5)

            elif self.test_case_no == 219319:
                # connection with TX based BSSID in WPA2 security mode, and NT based BSSID in WPA3 security mode
                for i in range(0, 6):
                    self.verfiy_T_and_NT_based_mbssid_in_dut_list()

            elif self.test_case_no == 219320:
                # connection with TX based BSSID in WPA3 security mode, and NT based BSSID in WPA3 security mode
                for i in range(0, 6):
                    self.verfiy_T_and_NT_based_mbssid_in_dut_list()

            elif self.test_case_no == 219321:
                # connection with TX based BSSID in WPA2 security mode, and NT based BSSID in WPA3 security mode
                for i in range(0, 6):
                    self.verfiy_T_and_NT_based_mbssid_in_dut_list()

            elif self.test_case_no == 219307:
                ping_count = 10
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                time.sleep(2)

                self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                               static_subnet="255.255.255.0",
                                                               static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                self.wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="Open", channel=3,
                                                       dtim_beacon_count=1,
                                                       beacon_interval=100)
                logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
                self.wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.Open)
                time.sleep(2)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         power_save=False,
                                                                         ping_after_power_save=True, retry_count=3,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         )
                time.sleep(10)
                self.wifi_client.interfaces.wifi.leave()

            elif self.test_case_no == 219308:
                ping_count = 10
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                time.sleep(2)
                self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                               static_subnet="255.255.255.0",
                                                               static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                self.wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="Open", channel=3,
                                                       dtim_beacon_count=1,
                                                       beacon_interval=100)
                logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
                self.wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.Open)
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.scan()
                self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                   security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase)

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=False, power_save=False
                                                                         , ping_after_power_save=False, skip_scan=True,
                                                                         skip_connect=True)
                time.sleep(10)
                self.wifi_client.interfaces.wifi.leave()

            elif self.test_case_no == 219309:
                ping_count = 10
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                time.sleep(2)
                self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                               static_subnet="255.255.255.0",
                                                               static_gateway="192.168.100.76")

                self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                                    channel=self.channel,
                                                                                    ssid=self.ssid,
                                                                                    security=self.security,
                                                                                    password=self.password,
                                                                                    dtim_count=self.dtim_count,
                                                                                    beacon_interval=self.beacon_interval,
                                                                                    ping_count=ping_count,
                                                                                    no_of_clients=self.no_of_clients,
                                                                                    leave=False
                                                                                    )
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         power_save=False, skip_scan=True,
                                                                         ping_after_power_save=True, retry_count=3,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         )

            elif self.test_case_no == 219310:
                ping_count = 10
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()

                time.sleep(2)
                logger().info(" ********** Starting DUT as an AP ********* ")
                self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                               static_subnet="255.255.255.0",
                                                               static_gateway="192.168.100.76")

                self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                                    channel=self.channel,
                                                                                    ssid=self.ssid,
                                                                                    security=self.security,
                                                                                    password=self.password,
                                                                                    dtim_count=self.dtim_count,
                                                                                    beacon_interval=self.beacon_interval,
                                                                                    ping_count=ping_count,
                                                                                    no_of_clients=self.no_of_clients,
                                                                                    leave=False
                                                                                    )
                time.sleep(5)
                self.wifi_dut.interfaces.wifi.scan()
                self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                   security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=False, power_save=False
                                                                         , ping_after_power_save=False, skip_scan=True,
                                                                         skip_connect=True, retry_count=3)

            elif self.test_case_no == 219311:
                ping_count = 10
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                time.sleep(2)
                self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                               static_subnet="255.255.255.0",
                                                               static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                self.wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="wpa3_transition", channel=3,
                                                       dtim_beacon_count=1,
                                                       beacon_interval=100)

                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.
                    MgmtFrameProtectionRequired)

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         power_save=False,
                                                                         ping_after_power_save=True, retry_count=3,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         )

            elif self.test_case_no == 219312:
                ping_count = 10
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                time.sleep(2)
                self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                               static_subnet="255.255.255.0",
                                                               static_gateway="192.168.100.76")
                logger().info(" ********** Starting DUT as an AP ********* ")
                self.wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="wpa3_transition", channel=3,
                                                       dtim_beacon_count=1,
                                                       beacon_interval=100)

                time.sleep(10)
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.
                    MgmtFrameProtectionRequired)
                self.wifi_dut.interfaces.wifi.scan()
                self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                   security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=False
                                                                         , ping_after_power_save=False, skip_scan=True,
                                                                         skip_connect=True, power_save=False)
                time.sleep(10)
                self.wifi_client.interfaces.wifi.leave()

            elif self.test_case_no == 219315:
                self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid

                # Initiate scan to find all available SSID in DUT scan list T & NT based BSSID
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                time.sleep(10)

                for i in range(0, 6):
                    # Initiate the connection again for T based BSSID
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             ping_after_power_save=False)
                    packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="power_mgmt_bit")

                    self.sl_collections.ping(self.dut_addr['device_ip'], ping_count=60)
                    self.wifi_dut.interfaces.wifi.leave()
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    time.sleep(2)
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                        'packet_count'], \
                        'Unable to find NULL-Data frame packets with power save bit 1'

                    # Initiate the connection again for NT based BSSID
                    vap0_mbssid = self.find_vaps_mbssid()
                    logger().info(f"VAP0 MBSSID = {vap0_mbssid}")
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

                    self.wifi_dut.interfaces.wifi.scan()
                    self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                       security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                       passphrase=self.wifi_access_point.interfaces.wifi.passphrase)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=False
                                                                             , ping_after_power_save=False, skip_scan=True,
                                                                             skip_connect=True, retry_count=3)
                    time.sleep(10)
                    packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=vap0_mbssid, filter_name="power_mgmt_bit")

                    self.sl_collections.ping(self.dut_addr['device_ip'], ping_count=60)
                    self.wifi_dut.interfaces.wifi.leave()
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    time.sleep(2)
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                        'packet_count'], \
                        'Unable to find NULL-Data frame packets with power save bit 1'

            elif self.test_case_no == 219300:
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()

                self.wifi_dut.interfaces.wifi.join(ssid='""',
                                                   security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                   expected_negative_status=SLStatus.SL_STATUS_INVALID_PARAMETER)
            else:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , ping_after_power_save=False)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e

    def find_vaps_mbssid(self):
        vap0_bssid = ''
        # Regular expression pattern to match ssid and bssid
        pattern = r'ssid: (\S+) bssid: (\S+)'

        # Find all matches of the pattern in the scan_list string
        logger().info(f"\n\n Scan List = {self.scan_list}\n\n")
        matches = re.findall(pattern, str(self.scan_list))

        # Convert the list of tuples to a list of dictionaries
        ssid_bssid_list = [{'ssid': ssid, 'bssid': bssid} for ssid, bssid in matches]
        for i in range(len(ssid_bssid_list)):
            if ssid_bssid_list[i]['ssid'] == 'FROM_TEST_1':
                vap0_bssid = ssid_bssid_list[i]['bssid'].replace('),', '')
                break
        return vap0_bssid

    def find_mbssid_vaps(self):
        packet_filter = '                    SSID:'
        count = 0
        ssid_list = []
        final_ssid_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()

        logger().info(f'\n\n *** Trying to collect all T & NT based SSID from beacon packet *** \n\n')
        for x in line:
            if packet_filter in x:
                print(x)
                ssid_list.append(x)
                output = ssid_list[count].strip().split(':')[1].strip().replace('"', "")
                final_ssid_list.append(output)
                count = count + 1
        return final_ssid_list

    def find_ssid_list_from_dut_scan(self):
        ssid_list = []
        self.scan_list = self.wifi_dut.interfaces.wifi.scan()
        logger().info(f'\n\n *** Start to collect all available ssid in DUT scan list ***\n\n')
        for i in range(0, len(self.scan_list)):
            ssid_list.append(self.scan_list[i].ssid)
        logger().info(f'\n\n SSID LIST ={ssid_list}\n\n')
        return ssid_list

    def compare_list(self, list1, list2):
        """Returns True if list1 contains all elements of list2, False otherwise."""
        counter1 = Counter(list1)
        counter2 = Counter(list2)
        logger().info(f'***** Counter1 = {counter1}')
        logger().info(f'***** Counter2 = {counter2}')

        # Check if counter2 is a subset of counter1
        return all(counter2[element] <= counter1[element] for element in counter1)

    def verfiy_T_and_NT_based_mbssid_in_dut_list(self):
        packet_filter2 = '                    SSID:'
        ssid_list = self.find_ssid_list_from_dut_scan()
        time.sleep(2)
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address,
            radio_ch=self.wifi_access_point.interfaces.wifi.channel,
            filter_name='beacon_mbssid')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                       packet_filter2=packet_filter2)[
            'packet_count'], \
            'Unable to find MBSSID bit enable in extended capability field in sniffer capture'

        vap_list = self.find_mbssid_vaps()
        ''' Start verification for T & NT based scan list is available in DUT scan list '''
        assert self.compare_list(vap_list, ssid_list), 'Unable to match DUT ssid list with configured VAP list'
        logger().info("\n\n ***** DUT is able to scan all VAP's info ***** \n\n")
        return vap_list


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_c219284(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    packet_filter2 = '                .1.. .... = Multiple BSSID: Supported'

    '''	Verify whether DUT is able to send probe req/Assoc req with MBSSID support when enabled MBSSID 
        feature( Multiple BSSID field of the Extended Capabilities element)'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          ping_count=ping_count, test_case_no=219284, test_name=test_name,
                          sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info(f"\n\n\n DUT MAC Address = {wlan_obj.dut_addr['dut_mac_address']}\n\n")
        time.sleep(60)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name='assoc_mbssid')

        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

        time.sleep(2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)['packet_count'], \
            'Unable to find MBSSID bit enable in extended capability field in sniffer capture'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_scan_all_vap_c219285(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                              sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    '''Verify whether DUT is able to scan all VAP's info when enabled MBSSID feature in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sniffer_filter=sniffer_filter, ping_count=ping_count, test_name=test_name,
                          sl_collections=sl_collections, test_case_no=219285)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_T_open_sec_c219286(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                            sniffer_filter, sl_collections, net_perf_client, wifi_client, protocol):
    
    test_name = request.node.name

    '''Verify whether DUT is able to connect to T profile BSSID with open security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, test_case_no=219286, test_name=test_name,
                          sniffer_filter=sniffer_filter, protocol=protocol,net_perf_client=net_perf_client,
                          wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_T_wpa2_psk_c219287(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                            sniffer_filter, sl_collections, net_perf_client, wifi_client, protocol):
    
    test_name = request.node.name

    '''Verify whether DUT is able to connect to T profile BSSID with WPA2 PSK security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, test_case_no=219286, test_name=test_name,
                          sniffer_filter=sniffer_filter, protocol=protocol, net_perf_client=net_perf_client,
                          wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA2',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA2"}]
})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_NT_wpa2_psk_c219288(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                             sniffer_filter, sl_collections, net_perf_client, wifi_client, protocol):
    
    test_name = request.node.name
    '''Verify whether DUT is able to connect to NT based profile BSSID with WPA2 PSK security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, test_case_no=219288, test_name=test_name,
                          sniffer_filter=sniffer_filter, protocol=protocol,
                          net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise e


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA3',
    'ssid': 'Mbssid_ap',
    'passphrase': '123456789',
    'channel': 3,
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA2"}]
})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.
        CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.
        SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_mbssid_T_wpa3_c219289(wifi_sniffer, wifi_access_point, wifi_dut, request,
                                        sniffer_filter, sl_collections, net_perf_client, wifi_client, protocol):
    test_name = request.node.name
    '''Verify whether DUT is able to connect to T profile BSSID with WPA3 Personal security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, test_case_no=219289, protocol=protocol, test_name=test_name,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA3',
    'ssid': 'Mbssid_ap',
    'passphrase': '123456789',
    'channel': 3,
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA3"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA3"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA3"}]
})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.
        CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.
        SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_mbssid_NT_wpa3_c219290(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                         sniffer_filter, sl_collections, net_perf_client, wifi_client, protocol):
    test_name = request.node.name

    '''Verify whether DUT is able to connect to NT profile BSSID with WPA3 Personal security enabled in AP'''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, test_case_no=219290, protocol=protocol, test_name=test_name,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_client=wifi_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise e


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
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
def test_wifi_sdk_mbssid_T_wpa2_enterprise_c219291(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, multicast_client,
                                                   radius_server, sl_collections, request, net_perf_client, wifi_client
                                                   , protocol):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method with multicast traffic"""
    try:
        test_name = request.node.name
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              sl_collections=sl_collections, test_case_no=219291, test_name=test_name, wifi_client=wifi_client,
                              sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, protocol=protocol, multicast_client=multicast_client)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip(reason="AP does not support WPA2 Enterprise in NT BSSID")
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
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA2Enterprise',
    "passphrase": '123456789',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": 'WPA2Enterprise'},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": 'WPA2Enterprise'},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": 'WPA2Enterprise'}]
})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_mbssid_NT_wpa2_enterprise_c219292(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                    sniffer_filter, sl_collections, net_perf_client, wifi_client,
                                                    protocol):
    test_name = request.node.name
    '''Verify whether DUT is able to connect to NT profile BSSID with WPA2 enterprise security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, test_case_no=219292, protocol=protocol, test_name=test_name,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_rejoin_T_open_sec_c219293(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                   sniffer_filter, sl_collections, net_perf_client, wifi_client, switch,
                                                   protocol):
    
    test_name = request.node.name

    '''Verify whether DUT is able to rejoin to T profile BSSID with open security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, test_case_no=219293, test_name=test_name,
                          sniffer_filter=sniffer_filter, protocol=protocol, switch=switch,net_perf_client=
                          net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)
        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)

        sl_collections.ping(wlan_obj.dut_addr['device_ip'], ping_count=60)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_rejoin_T_wpa2_c219294(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                               sniffer_filter, sl_collections, net_perf_client, wifi_client, switch,
                                               protocol):
    
    test_name = request.node.name

    '''Verify whether DUT is able to rejoin to T profile BSSID with WPA2 PSK security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219293,
                          sniffer_filter=sniffer_filter, switch=switch, t_profile_bssid=t_profile_bssid,
                          net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)

        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)

        sl_collections.ping(wlan_obj.dut_addr['device_ip'], ping_count=60)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA2',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA2"}]
})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_rejoin_NT_wpa2_c219295(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                sniffer_filter, sl_collections, net_perf_client, wifi_client, protocol,
                                                switch):
    
    test_name = request.node.name

    '''Verify whether DUT is able to rejoin to NT profile BSSID with WPA2 PSK security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219295,
                          protocol=protocol,
                          sniffer_filter=sniffer_filter, switch=switch, t_profile_bssid=t_profile_bssid,
                          net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)

        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)

        sl_collections.ping(wlan_obj.dut_addr['device_ip'], ping_count=60)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.
        CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.
        SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_mbssid_rejoin_T_wpa3_c219296(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                               sniffer_filter, sl_collections, net_perf_client, wifi_client, switch,
                                               protocol):
    
    test_name = request.node.name

    '''Verify whether DUT is able to rejoin to T profile BSSID with WPA3 Personal security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219289,
                          sniffer_filter=sniffer_filter, switch=switch, t_profile_bssid=t_profile_bssid,
                          net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol)
    try:
        logger().info("\n *** Enable Rejoin *** \n")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40,
                                                                 first_time_retry_enable=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)

        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)

        sl_collections.ping(wlan_obj.dut_addr['device_ip'], ping_count=60)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA3',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA3"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA3"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA3"}]
})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.
        CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.
        SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_mbssid_rejoin_NT_wpa3_c219297(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                sniffer_filter, sl_collections, net_perf_client, wifi_client, switch,
                                                protocol):
    
    test_name = request.node.name

    '''Verify whether DUT is able to rejoin to NT profile BSSID with WPA3 Personal security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219290,
                          sniffer_filter=sniffer_filter, switch=switch, t_profile_bssid=t_profile_bssid,
                          net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol)
    try:
        logger().info("\n *** Enable Rejoin *** \n")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40,
                                                                 first_time_retry_enable=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)

        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)
        sl_collections.ping(wlan_obj.dut_addr['device_ip'], ping_count=60)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_c219298(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    packet_filter2 = '                .1.. .... = Multiple BSSID: Supported'

    '''	Connection with Wrong security '''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          ping_count=ping_count, test_name=test_name, test_case_no=219298,
                          sl_collections=sl_collections, sniffer_filter=sniffer_filter)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_c219299(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    '''	Connection with Wrong security '''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          ping_count=ping_count, test_name=test_name, test_case_no=219299,
                          sniffer_filter=sniffer_filter,
                          sl_collections=sl_collections)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA2',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA2"}]
})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_connection_failure_c219300(wifi_sniffer, wifi_access_point, wifi_dut, request,
                                             sniffer_filter, sl_collections):
    test_name = request.node.name

    '''continuous connect disconnect b/w T and NT profile based SSID's'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, test_case_no=219300, test_name=test_name,
                          sniffer_filter=sniffer_filter)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise e


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_c219301(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    '''	Connect & disconnect(10 times) when STA connected to TXBSSID '''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          ping_count=ping_count, test_name=test_name, test_case_no=219301,
                          sniffer_filter=sniffer_filter,
                          sl_collections=sl_collections)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA2',
    'ssid': 'Mbssid_ap',
    'passphrase': '123456789',
    'channel': 3,
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA2"}]
})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_c219302(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    '''	Connect & disconnect(10 times) when STA connected to NT BSSID '''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          ping_count=ping_count, test_name=test_name, test_case_no=219302,
                          sniffer_filter=sniffer_filter, sl_collections=sl_collections)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA2',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA3"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA3"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA3"}]
})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.
        CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.
        SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_mbssid_c219319(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    '''	Verify whether DUT is able to scan all VAP's info when enabled MBSSID feature in AP and  each VAP different  
    security(TX based Vap - WPA2 Personal & NT based VAP - WPA3 security '''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          ping_count=ping_count, test_name=test_name, test_case_no=219319,
                          sl_collections=sl_collections, sniffer_filter=sniffer_filter)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA3',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA3"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA3"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA3"}]
})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.
        CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.
        SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_mbssid_c219320(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    '''	Verify whether DUT is able to scan all VAP's info when enabled MBSSID feature in AP and each VAP different 
    security(TX based Vap - WPA3 Personal & NT based VAP - WPA3 Transition security '''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          ping_count=ping_count, test_name=test_name, test_case_no=219320,
                          sl_collections=sl_collections, sniffer_filter=sniffer_filter)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'Open',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA2"}]
})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_c219321(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    '''	Verify whether DUT is able to scan all VAP's info when enabled MBSSID feature in AP and each VAP different 
        security(TX based Vap - Open & NT based VAP - WPA2 Personal security '''
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          ping_count=ping_count, test_name=test_name, test_case_no=219321,
                          sl_collections=sl_collections, sniffer_filter=sniffer_filter)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_client",
    wifi={
        "ssid": "SILABS_AP_MODE",
        "channel": 3,
        "interface": "wlan0",
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'Open',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "band": "2g", "security": "Open", 'channel': 3},
        {"index": "2", "ssid": "FROM_TEST_2", "band": "2g", "security": "Open", 'channel': 3},
        {"index": "3", "ssid": "FROM_TEST_3", "band": "2g", "security": "Open", 'channel': 3}]
})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_T_profile_based_ap_open_sec_c219307(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                             request,
                                                             sniffer_filter, sl_collections, net_perf_client,
                                                             wifi_client):
    
    test_name = request.node.name

    '''Verify whether DUT is able to connect to T profile BSSID with open security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219307,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.stop_ap()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_client",
    wifi={
        "ssid": "SILABS_AP_MODE",
        "channel": 3,

        "interface": "wlan0",
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'Open',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "band": "2g", "security": "Open", 'channel': 3},
        {"index": "2", "ssid": "FROM_TEST_2", "band": "2g", "security": "Open", 'channel': 3},
        {"index": "3", "ssid": "FROM_TEST_3", "band": "2g", "security": "Open", 'channel': 3}]
})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_NT_profile_based_ap_open_sec_c219308(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                              request,
                                                              sniffer_filter, sl_collections, net_perf_client,
                                                              wifi_client):
    
    test_name = request.node.name

    '''Verify whether DUT is able to connect to NT profile BSSID with open security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219308,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.stop_ap()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 3,
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
        'channel': 3,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_T_profile_based_ap_wpa2_sec_c219309(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                             request, sniffer_filter, sl_collections, net_perf_client,
                                                             wifi_clients):
    
    test_name = request.node.name

    '''Verify whether DUT is able to connect to T profile BSSID with WPA2 security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219309,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_clients=wifi_clients)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.stop_ap()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 3,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': '123456789',
        'channel': 3,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA2',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA2"}]
})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_NT_profile_based_ap_wpa2_sec_c219310(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                              request, sniffer_filter, sl_collections, net_perf_client,
                                                              wifi_clients):
    
    test_name = request.node.name

    '''Verify whether DUT is able to connect to NT profile BSSID with WPA2 security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219310,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_clients=wifi_clients)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.stop_ap()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA3",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 3,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    'ssid': 'Concurent_ap',
    'passphrase': '123456789',
    'channel': 3,
    "security": 'WPA3',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA3"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA3"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA3"}]
})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.
        CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.
        SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_T_profile_based_ap_wpa3_sec_c219311(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                             request,
                                                             sniffer_filter, sl_collections, net_perf_client,
                                                             wifi_clients):
    
    test_name = request.node.name

    '''Verify whether DUT is able to connect to T profile BSSID with WPA3 security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219311,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_clients=wifi_clients)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.stop_ap()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA3",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 3,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA3',
    'ssid': 'Concurent_ap',
    'passphrase': '123456789',
    'channel': 3,
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA3"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA3"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA3"}]
})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.
        CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.
        SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_NT_profile_based_ap_wpa3_sec_c219312(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                              request,
                                                              sniffer_filter, sl_collections, net_perf_client,
                                                              wifi_client):
    
    test_name = request.node.name

    '''Verify whether DUT is able to connect to NT profile BSSID with WPA3 security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219312,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.stop_ap()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point", wifi={
    "standard": 'gnbax',
    "security": 'WPA2',
    "guest_networks": [
        {"index": "1", "ssid": "FROM_TEST_1", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "2", "ssid": "FROM_TEST_2", "passphrase": '123456789', "band": "2g", "security": "WPA2"},
        {"index": "3", "ssid": "FROM_TEST_3", "passphrase": '123456789', "band": "2g", "security": "WPA2"}]
})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_T_NT_connect_disconnect_c219315(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                             sniffer_filter, sl_collections, net_perf_client, wifi_client, protocol):
    
    test_name = request.node.name

    '''continuous connect disconnect b/w T and NT profile based SSID's'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, test_case_no=219315, test_name=test_name,
                          sniffer_filter=sniffer_filter, protocol=protocol, net_perf_client=net_perf_client,
                          wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise e





