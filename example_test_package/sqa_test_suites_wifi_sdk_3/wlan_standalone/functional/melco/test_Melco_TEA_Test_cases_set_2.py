import time
import pytest
import ipaddress
from utf.utils.iperf.iperf_utils import ping
from random import randint
import random
import string
from utf.utf_config import UtfConfig
import re
from utf.interfaces.wifi import SecurityMode
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.wifi import WlanError
from utf.utils import print_dict
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xRegion, Si91xRegionCode, Si91xModuleType
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from threading import Thread


def logger():
    return get_logger(__name__)


class AP11nParamsEnabled(ThreadBase):
    def __init__(self, wifi_dut, wifi_clients, wifi_sniffer,
                 sl_collections, utf_constants, net_perf_client=None, protocol=None,
                 testcase_no=None, capture_filename=None, dtim_period=None, beacon=None,
                 traffic_type=None, leave=True, enable_data_rate=False, network_interface=None,
                 sniffer_stop=False, htcaps_enable=None, ssid=None, security=None, device_ip=None,
                 password=None, dtim_count=None, beacon_interval=None, remote_ip=None,
                 channel=None, no_of_clients=None, ht_caps=None, timeout=60,
                 ipv6_addr_type="global", wifi_client=None, wifi_access_point=None, beacon_stop=None,
                 sniffer_filter=None, dut_addr_dict=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.device_ip = device_ip
        self.network_interface = network_interface
        self.dut_addr_dict=dut_addr_dict
        self.sniffer_filter = sniffer_filter
        self.wifi_client = wifi_client
        self.wifi_clients = wifi_clients
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.utf_constants = utf_constants
        self.capture_filename = capture_filename
        self.testcase_no = testcase_no
        self.dtim_period = dtim_period
        self.beacon = beacon
        self.traffic_type = traffic_type
        self.leave = leave
        self.enable_data_rate = enable_data_rate
        self.sniffer_stop = sniffer_stop
        self.htcaps_enable = htcaps_enable
        self.ssid = ssid
        self.security = security
        self.password = password
        self.dtim_count = dtim_count
        self.beacon_interval = beacon_interval
        self.channel = channel
        self.no_of_clients = no_of_clients
        self.ht_caps = ht_caps
        self.ipv6_addr_type = ipv6_addr_type
        self.beacon_stop = beacon_stop
        self.timeout = timeout
        self.remote_ip = remote_ip

    def run_wifi_traffic(self, wifi_dut=None, net_perf_client=None, protocol=None, device_ip=None, host_ip=None,
                         timeout=60, traffic_type="TX", device=None, buffer_size_tcp=1460, buffer_size_udp=1470,
                         ip_version=4, async_socket=0, ipv6_address_type=None, link_interface=None):

        if ip_version == 6:
            protocol_family = 24
        else:
            protocol_family = 2
        self.network_interface = self.wifi_client.interfaces.wifi.config["v6_interface"]
        logger().info(f"printing the newly added interface {self.network_interface}")
        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.ipv6_addr_type, network_interface=self.network_interface)
        logger().info(f"remote_ip: {remote_ip}")
        ip_addr = ipaddress.ip_address(remote_ip)
        self.remote_ip = ip_addr
        host_ip = self.remote_ip
        device_ip = self.info_attr['device_ip']
        logger().info (f"printing Host ip {host_ip}")
        logger().info(f"printing Device ip {device_ip}")
        if traffic_type == "TX":
            logger().info("starting the server from Remote device")
            # starting iperf
            net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip,
                                                            protocol=protocol, time_out=timeout, version=ip_version)
            net_perf_client.interfaces.net_perf.start()

            if protocol == "TCP":
                logger().info("sending data from DUT")
                wifi_dut.interfaces.wifi.iperf(family=protocol_family, transfer_type=1, protocol=6,
                                               local_port=net_perf_client.interfaces.net_perf.server_port,
                                               local_ip=device_ip, remote_ip=host_ip,
                                               remote_port=net_perf_client.interfaces.net_perf.server_port,
                                               size=buffer_size_tcp,
                                               ttl=timeout,
                                               throughput_type=1, qos=0,
                                               timeout=timeout + 20, ip_version=ip_version,
                                               async_socket=async_socket)
            elif protocol == "UDP":
                logger().info("sending data from DUT")
                wifi_dut.interfaces.wifi.iperf(family=protocol_family, transfer_type=2, protocol=17,
                                               local_port=net_perf_client.interfaces.net_perf.server_port,
                                               local_ip=device_ip, remote_ip=host_ip,
                                               remote_port=net_perf_client.interfaces.net_perf.server_port,
                                               size=buffer_size_udp,
                                               ttl=timeout,
                                               throughput_type=2, qos=0,
                                               timeout=timeout + 20, ip_version=ip_version,
                                               async_socket=async_socket)

            # # get and print throughput
            tp = net_perf_client.interfaces.net_perf.process_output()
            assert tp is not None, "Throughput not found"
            logger().info("data transfer is successful")
            net_perf_client.interfaces.net_perf.iperf_process.stop(5)

        if traffic_type == "RX":
            if ipv6_address_type == "link":
                device_ip_link = device_ip + "%" + str(link_interface)
                logger().info(f"device_ip_link inside sl_collections {device_ip_link}")
                net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip_link,
                                                                protocol=protocol, time_out=timeout,
                                                                version=ip_version)
                logger().info(f"Host IP: {host_ip}, Dut IP: {device_ip}, Protocol: {protocol}")
                logger().info(f"***** starting iperf ******")
            else:
                net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip,
                                                                protocol=protocol, time_out=timeout,
                                                                version=ip_version)
                logger().info(f"Host IP: {host_ip}, Dut IP: {device_ip}, Protocol: {protocol}")
                logger().info(f"***** starting iperf ******")

            def start_client():
                time.sleep(3)
                logger().info(f"***** start listening  ******")
                net_perf_client.interfaces.net_perf.start()

            if protocol == "TCP":
                client_thread1 = Thread(target=start_client, args=(), )
                client_thread1.start()
                wifi_dut.interfaces.wifi.iperf(family=protocol_family, transfer_type=1, protocol=6,
                                               local_port=net_perf_client.interfaces.net_perf.client_port,
                                               local_ip=device_ip, remote_ip=host_ip,
                                               remote_port=net_perf_client.interfaces.net_perf.client_port,
                                               size=buffer_size_tcp, ttl=timeout, throughput_type=3, qos=0,
                                               timeout=timeout + 20, ip_version=ip_version, async_socket=async_socket)

                client_thread1.join()

            elif protocol == "UDP":
                client_thread2 = Thread(target=start_client, args=(), )
                client_thread2.start()
                wifi_dut.interfaces.wifi.iperf(family=protocol_family, transfer_type=2, protocol=17,
                                               local_port=net_perf_client.interfaces.net_perf.client_port,
                                               local_ip=device_ip, remote_ip=host_ip,
                                               remote_port=net_perf_client.interfaces.net_perf.client_port,
                                               size=buffer_size_udp, ttl=timeout, throughput_type=4, qos=0,
                                               timeout=timeout + 20, ip_version=ip_version, async_socket=async_socket)

                client_thread2.join()

            logger().info("data transfer is successful")
            net_perf_client.interfaces.net_perf.iperf_process.stop(5)
            time.sleep(5)

    def run_traffic(self, protocol="TCP", traffic_type="TX", ip_version=6, link_interface=None):
        self.run_wifi_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=protocol,
            device_ip=self.device_ip,
            host_ip=self.remote_ip,
            timeout=self.timeout,
            traffic_type=traffic_type,
            ip_version= ip_version,
            buffer_size_tcp=1380,
            buffer_size_udp=1390,
            async_socket=1,
            ipv6_address_type="link",
            link_interface=self.network_interface
        )

    def sniffer_capture_start(self, channel=11, capture_filename="sniffer_capture"):
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)

        logger().info(f"channel number in which the sniffer capture is starting is {self.channel}")
        logger().info(
            f" ******* start capturing with Sniffer by giving the test case name as filename {self.capture_filename} ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        time.sleep(3)

    def raspi_sta_assoc_to_dut_ap(self, hidden_ssid=0):
        for i in range(0, self.no_of_clients):
            self.dut_add_dict = {}
            self.ping_count=10
            connected = False
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join(scan_ssid=hidden_ssid)
            time.sleep(5)
            self.dut_add_dict['dut_ip'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ip']}")
            for count in range(5):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{self.wifi_clients[i].name}' to DUT")
                    self.dut_add_dict['rasp_mac_address'] = self.wifi_clients[i].interfaces.wifi.get_mac_address()
                    logger().info(f"raspi_mac: {self.dut_add_dict['rasp_mac_address']}")
                    self.raspi_mac = self.dut_add_dict['rasp_mac_address']
                    self.dut_add_dict['client_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client_ip: {self.dut_add_dict['client_ip']}")
                    time.sleep(10)
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
        logger().info("Waiting 30 seconds to check connection stability")
        time.sleep(30)
        logger().info("Checking the connection stability after 30 seconds")

    def dut_aput_mac_addr_in_ap_alone_mode(self):
        dut_ap_mac_addr = self.dut_addr_dict["dut_mac_address"]
        logger().info(f" the dut_ap_mac_addr in ap alone mode {dut_ap_mac_addr}")
        return dut_ap_mac_addr

    def dut_sta_mac_addr_in_concur_mode(self):
        dut_sta_mac_addr = self.info_attr["dut_mac_address"]
        logger().info(f"The STA Mac address is {dut_sta_mac_addr}")
        return dut_sta_mac_addr

    def raspi_mac_addres(self):
        raspi_mac_addr = self.dut_addr_dict["rasp_mac_address"]
        logger().info(f"Printing the rapsi mac address is {raspi_mac_addr}")
        return raspi_mac_addr

    def check_no_beacons_from_aput(self):
        sa_addr = self.aput_mac_address()
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sa_addr,
            filter_name="beacon")
        logger().info(f"printing check_no_beacons_from_aput the vlaue of packet filter 1 {packet_filter1}")
        assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def check_beacons_from_aput(self, expected_beacons=True):
        sa_addr = self.aput_mac_address()
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sa_addr,
            filter_name="beacon")
        if expected_beacons:
            logger().info(f"printing checking beacons_from_aput the vlaue of packet filter 1 {packet_filter1}")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
        else:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                          negative_test=True)['packet_count'], \
                'found beacon frame  when stop ap enabled from DUT in Sniffer'
            logger().info("Beacon frame not found in sniffer when stop ap enabled from DUT")

    def aput_beacon_11n_params_check(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_aput_mac_addr_in_ap_alone_mode(),
            filter_name="beacon_HT_info")
        logger().info(
            f"Validating the 11n HT Parameter in Beacons from APUT after enabling the 11N Caps {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def aput_prb_rsp_11n_params_check(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_aput_mac_addr_in_ap_alone_mode(),
            ra_addr=self.raspi_mac_addres(),
            filter_name="probe_res_ht_info")
        logger().info(
            f"Validating the 11n HT Parameter in Probe Response from APUT after enabling the 11N Caps {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def aput_assoc_rsp_11n_params_check(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_aput_mac_addr_in_ap_alone_mode(),
            ra_addr=self.raspi_mac_addres(),
            filter_name="asso_res_ht_info")
        logger().info(
            f"Validating the 11n HT Parameter in Association Response from APUT after enabling the 11N Caps {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def staut_assoc_req_11ax_params_check(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_sta_mac_addr_in_concur_mode(),
            filter_name="assoc_request_he_element")
        logger().info(f"Checking HE  params in Asssoc Request Frame {packet_filter1}")
        assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def check_hidden_ssid_aput_beacon(self):
        sa_addr = self.aput_mac_address()
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sa_addr,
            hidden_ssid='\"\"',
            filter_name="hidden_ssid")
        logger().info(f"conforming the Hidden SSID In the APUT Beacons {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def check_hidden_ssid_aput_probe_response(self):
        sa_addr = self.aput_mac_address()
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sa_addr,
            hidden_ssid='\"\"',
            filter_name="hidden_ssid_probe_res")
        logger().info(f"Verifying the SSID Field in probe response packet with Hidden SSID Enabled in APUT{packet_filter1}")
        assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def check_hidden_ssid_staut_probe_request(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_sta_mac_addr_in_concur_mode(),
            hidden_ssid="\"\"",
            filter_name="hidden_ssid_probe_request_packet")
        logger().info(f"conforming the probe request from STA Interface {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    def sniffer_check(self):
        self.check_hidden_ssid_aput_beacon()

    def aput_start(self):
        time.sleep(3)
        ping_count = self.utf_constants.get("ping_count")

        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.wifi_dut.interfaces.wifi.start_ap(ssid="917_AP", security="wpa2", psk="12345678", channel=11,
                                               dtim_beacon_count=3,
                                               beacon_interval=100,
                                               ht_caps=1, beacon_stop=self.beacon_stop)

    def ping_async(self, ip_addr):

        self.logger.info(f"PINGING TO {ip_addr}")
        time.sleep(20)
        self.wifi_dut.interfaces.wifi.ping(server_ip=ip_addr, ip_version='ipv6', ping_size=64, num_ping_attempts=10)

    def remote_ipv6_address(self):
        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.ipv6_addr_type)
        logger().info(f"remote_ip address is: {remote_ip}")
        ip_addr = ipaddress.ip_address(remote_ip)
        return ip_addr

    def aput_mac_address(self):
        if self.testcase_no in [693684, 693688, 693686, 693691, 693698]:
            logger().info(f"inside If condition")
            self.ap_mac_in_ap_alone = self.wifi_dut.interfaces.wifi.get_mac_address()
        else:
            logger().info(f"inside else condition")
            self.ap_mac_in_ap_alone = self.wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"printing aput mac address {self.ap_mac_in_ap_alone}")
        return self.ap_mac_in_ap_alone


    def aput_client_connection(self):
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                            channel=11, ssid="917_AP",
                                                                            security="wpa2", password="12345678",
                                                                            dtim_count=3,
                                                                            beacon_interval=100,
                                                                            ht_caps=1,
                                                                            ping_count=10,
                                                                            no_of_clients=1,
                                                                            leave=self.leave,
                                                                            enable_data_rate=self.enable_data_rate,
                                                                            beacon_stop=self.beacon_stop
                                                                            )

        logger().info(f"printing the value of AP dut_addr_dict {self.dut_addr_dict}")

        # time.sleep(20)
        if self.testcase_no in [557309]:
            time.sleep(20)
            logger().info("stopping the sotap")
            # self.wifi_dut.interfaces.wifi.stop_ap()
            self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
            time.sleep(20)
            self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0",
                                                           static_gateway="192.168.100.76")
            self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                                channel=11, ssid="917_AP",
                                                                                security="wpa2", password="12345678",
                                                                                dtim_count=3,
                                                                                beacon_interval=100,
                                                                                ht_caps=1,
                                                                                ping_count=10,
                                                                                no_of_clients=1,
                                                                                leave=self.leave,
                                                                                enable_data_rate=self.enable_data_rate, )

            logger().info(f"printing the value of AP dut_addr_dict {self.dut_addr_dict}")

    def concurrent_sta_alone(self):
        ping_count = self.utf_constants.get("ping_count")
        self.info_attr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                  wifi_access_point=self.wifi_access_point,
                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                  ip_config_disable=False,
                                                                  ip_version='ipv6',
                                                                  power_save=False, retry_count=3,
                                                                  ping_before_power_save=False,
                                                                  ping_after_power_save=False,
                                                                  ipv6_type=self.ipv6_addr_type
                                                                  )
        logger().info(f"printing value of STA Interface info_attr {self.info_attr}")
        time.sleep(20)
        device_ip = self.info_attr['device_ip']
        self.ping_async(device_ip)

    def concu_aput_start(self):
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                            channel=11, ssid="917_AP",
                                                                            security="wpa2", password="12345678",
                                                                            dtim_count=3,
                                                                            beacon_interval=100,
                                                                            ht_caps=1,
                                                                            ping_count=10,
                                                                            no_of_clients=1,
                                                                            leave=self.leave,
                                                                            enable_data_rate=self.enable_data_rate,
                                                                            beacon_stop=self.beacon_stop, )

    def concurrent_sta(self):
        ping_count = self.utf_constants.get("ping_count")
        self.info_attr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                  wifi_access_point=self.wifi_access_point,
                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                  ip_config_disable=False,
                                                                  ip_version='ipv6',
                                                                  power_save=False, retry_count=3,
                                                                  ping_before_power_save=False,
                                                                  ping_after_power_save=False,
                                                                  ipv6_type=self.ipv6_addr_type
                                                                  )
        logger().info(f"printing value of STA Interface info_attr {self.info_attr}")
        time.sleep(20)
        self.network_interface = self.wifi_client.interfaces.wifi.config["v6_interface"]
        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.ipv6_addr_type,
                                                                    network_interface=self.network_interface)
        logger().info(f"remote_ip: {remote_ip}")
        ip_addr = ipaddress.ip_address(remote_ip)
        self.ping_async(ip_addr=ip_addr)

        device_ip = self.info_attr['device_ip']
        logger().info(f"device_ip : {device_ip}")

        if self.ipv6_addr_type == "link":
            interface = self.wifi_client.interfaces.wifi.config["v6_interface"]
            device_ip = f"{device_ip}%{interface}"
            status = ping(device_ip, 10)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "scan_ssid":1,
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.test_src_map_id('C693684')
def test_wifi_sdk_check_aput_beacons_with_hidden_ssid_enabled_c693684(wifi_dut, wifi_sniffer, sl_collections,
                                                                      wifi_clients, utf_constants, sniffer_filter
                                                                      ):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants,
                                        sniffer_filter=sniffer_filter,
                                        testcase_no=693684, channel=11, capture_filename="TC693684_Sniffer")
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_beacons_from_aput()
        ap_dut_obj.check_hidden_ssid_aput_beacon()
        time.sleep(10)

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 4096}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11
                               }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "scan_ssid":1,
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C693685')
def test_wifi_sdk_check_hidden_ssid_in_concurrent_mode_with_sta_tx_traffic_c693685(wifi_dut, wifi_sniffer,
                                                                                   sl_collections, wifi_client,
                                                                                   wifi_clients, utf_constants,
                                                                                   sniffer_filter, net_perf_client,
                                                                                   wifi_access_point,protocol):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants,
                                        sniffer_filter=sniffer_filter, wifi_access_point=wifi_access_point,
                                        testcase_no=693687, channel=11, capture_filename="TC693685_Sniffer",
                                        beacon_stop=0, net_perf_client=net_perf_client,protocol=protocol,
                                        wifi_client=wifi_client, no_of_clients=1)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.concurrent_sta()
        ap_dut_obj.aput_start()
        time.sleep(4)
        ap_dut_obj.raspi_sta_assoc_to_dut_ap(hidden_ssid=1)
        ap_dut_obj.run_traffic(protocol="TCP", traffic_type="TX", ip_version=6)
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_hidden_ssid_aput_beacon()

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "scan_ssid":1,
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US",
        }
    }
)
@pytest.mark.test_src_map_id('C693688')
def test_wifi_sdk_check_aput_probe_response_with_hidden_ssid_enabled_c693688(wifi_dut, wifi_sniffer, sl_collections,
                                                                             wifi_clients, utf_constants, sniffer_filter
                                                                             ):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants,
                                        sniffer_filter=sniffer_filter,no_of_clients= 1,
                                        testcase_no=693688, channel=11, capture_filename="TC693688_Sniffer")
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        ap_dut_obj.raspi_sta_assoc_to_dut_ap(hidden_ssid=1)
        logger().info("Stop sniffer finally")
        time.sleep(30)
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_hidden_ssid_aput_beacon()
        ap_dut_obj.check_hidden_ssid_aput_probe_response()
        time.sleep(10)

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "scan_ssid":1,
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.test_src_map_id('C693686')
def test_wifi_sdk_check_beacon_stop_with_hidden_ssid_enabled_c693686(wifi_dut, wifi_sniffer, sl_collections,
                                                                     wifi_clients, utf_constants, sniffer_filter
                                                                     ):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants,
                                        sniffer_filter=sniffer_filter, no_of_clients= 1,
                                        testcase_no=693686, channel=11, capture_filename="TC693686_Sniffer",
                                        beacon_stop=1)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        time.sleep(10)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_no_beacons_from_aput()
        time.sleep(10)
        ap_dut_obj.sniffer_capture_start(capture_filename="TC693686_Sniffer_cap_2")
        ap_dut_obj.raspi_sta_assoc_to_dut_ap(hidden_ssid=1)
        ap_dut_obj.check_beacons_from_aput()
        ap_dut_obj.check_hidden_ssid_aput_beacon()


    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11
                               }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "scan_ssid":1,
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.test_src_map_id('C693687')
def test_wifi_sdk_check_hidden_ssid_in_concurrent_mode_with_sta_conn_c693687(wifi_dut, wifi_sniffer, sl_collections,
                                                                             wifi_clients, utf_constants,
                                                                             sniffer_filter,
                                                                             wifi_access_point, wifi_client):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants,no_of_clients= 1,
                                        sniffer_filter=sniffer_filter, wifi_access_point=wifi_access_point,
                                        testcase_no=693687, channel=11, capture_filename="TC693687_Sniffer",
                                        beacon_stop=1, wifi_client=wifi_client)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.concurrent_sta()
        ap_dut_obj.aput_start()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_no_beacons_from_aput()
        time.sleep(4)
        ap_dut_obj.sniffer_capture_start(capture_filename="TC693687_Sniffer_2")
        ap_dut_obj.raspi_sta_assoc_to_dut_ap(hidden_ssid=1)
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_beacons_from_aput()
        ap_dut_obj.check_hidden_ssid_aput_beacon()

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11
                               }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "scan_ssid":1,
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.test_src_map_id('C693689')
def test_wifi_sdk_check_hidden_ssid_in_aput_prb_respnse_staut_prb_req_in_cncurnt_mode_c693689(wifi_dut, wifi_sniffer,
                                                                                              sl_collections,
                                                                                              wifi_client,
                                                                                              wifi_clients,
                                                                                              utf_constants,
                                                                                              sniffer_filter,
                                                                                              wifi_access_point):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants,no_of_clients= 1,
                                        sniffer_filter=sniffer_filter, wifi_access_point=wifi_access_point,
                                        testcase_no=693687, channel=11, capture_filename="TC693689_Sniffer",
                                        beacon_stop=0, ipv6_addr_type="link", wifi_client=wifi_client)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.concurrent_sta()
        ap_dut_obj.aput_start()
        time.sleep(4)
        ap_dut_obj.raspi_sta_assoc_to_dut_ap(hidden_ssid=1)
        ap_dut_obj.remote_ipv6_address()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_beacons_from_aput()
        ap_dut_obj.check_hidden_ssid_aput_probe_response()
        ap_dut_obj.check_hidden_ssid_aput_beacon()
        ap_dut_obj.check_hidden_ssid_staut_probe_request()

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11
                               }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "scan_ssid":1,
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.test_src_map_id('C693669')
def test_wifi_sdk_check_scan_in_staut_mode_lab_environment_c693669(wifi_dut, wifi_sniffer,
                                                                   sl_collections,
                                                                   wifi_clients,
                                                                   utf_constants,
                                                                   sniffer_filter,
                                                                   wifi_access_point):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants,no_of_clients= 1,
                                        sniffer_filter=sniffer_filter, wifi_access_point=wifi_access_point,
                                        testcase_no=693687, channel=11, capture_filename="c693669_Sniffer",
                                        beacon_stop=0)
        ap_dut_obj.sniffer_capture_start()
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=11)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan_list not found"

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11
                               }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "scan_ssid":1,
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.test_src_map_id('C693673')
def test_wifi_sdk_check_scan_in_staut_mode_with_3rd_part_sta_conn_with_aput_c693673(wifi_dut, wifi_sniffer,
                                                                                    sl_collections,
                                                                                    wifi_clients,
                                                                                    utf_constants,
                                                                                    sniffer_filter,
                                                                                    wifi_access_point):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants,no_of_clients= 1,
                                        sniffer_filter=sniffer_filter, wifi_access_point=wifi_access_point,
                                        testcase_no=693687, channel=11, capture_filename="c693673_Sniffer",
                                        beacon_stop=0)

        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        ap_dut_obj.raspi_sta_assoc_to_dut_ap(hidden_ssid=1)
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=11)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan_list not found"

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11
                               }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.test_src_map_id('C693677')
def test_wifi_sdk_check_disconnect_sta_from_3rdparty_ap_c693677(wifi_dut, wifi_sniffer,
                                                                sl_collections,
                                                                wifi_clients,
                                                                utf_constants,
                                                                sniffer_filter,
                                                                wifi_access_point):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants, no_of_clients=1,
                                        sniffer_filter=sniffer_filter, wifi_access_point=wifi_access_point,
                                        testcase_no=693687, channel=11, capture_filename="c693677_Sniffer",
                                        beacon_stop=0)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.concurrent_sta_alone()

        ''' code for the disconnect the sta from 3rd party AP has to be added '''
    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11
                               }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C693690')
def test_wifi_sdk_check_aput_enabling_with_sl_net_init_deinit_c693690(wifi_dut, wifi_sniffer,
                                                                      sl_collections,
                                                                      wifi_clients,
                                                                      utf_constants,
                                                                      sniffer_filter,
                                                                      wifi_access_point):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants, no_of_clients=1,
                                        sniffer_filter=sniffer_filter, wifi_access_point=wifi_access_point,
                                        testcase_no=693687, channel=11, capture_filename="c693690_Sniffer",
                                        beacon_stop=0)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_beacons_from_aput()

        wifi_dut.interfaces.wifi.sl_net_down(mode="ap")
        time.sleep(5)
        ap_dut_obj.sniffer_capture_start()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_beacons_from_aput(expected_beacons=False)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_beacons_from_aput()
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.raspi_sta_assoc_to_dut_ap(hidden_ssid=1)
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11
                               }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C693691')
def test_wifi_sdk_check_aput_enabling_with_sl_net_init_deinit_with_beacon_stop_enabled_c693691(wifi_dut, wifi_sniffer,
                                                                                               sl_collections,
                                                                                               wifi_clients,
                                                                                               utf_constants,
                                                                                               sniffer_filter,
                                                                                               wifi_access_point):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants, no_of_clients=1,
                                        sniffer_filter=sniffer_filter, wifi_access_point=wifi_access_point,
                                        testcase_no=693691, channel=11, capture_filename="c693691_Sniffer",
                                        beacon_stop=1)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_beacons_from_aput(expected_beacons=False)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.raspi_sta_assoc_to_dut_ap()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_beacons_from_aput()
        wifi_dut.interfaces.wifi.sl_net_down(mode="ap")
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        ap_dut_obj.raspi_sta_assoc_to_dut_ap()
        ap_dut_obj.check_beacons_from_aput()

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.HiddenSSID | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11
                               }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.test_src_map_id('C693698')
def test_wifi_sdk_check_ssid_in_beacons_with_3rd_party_sta_disconn_c693698(wifi_dut, wifi_sniffer,
                                                                           sl_collections,
                                                                           wifi_clients,
                                                                           utf_constants,
                                                                           sniffer_filter,
                                                                           wifi_access_point):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants, no_of_clients=1,
                                        sniffer_filter=sniffer_filter, wifi_access_point=wifi_access_point,
                                        testcase_no=693698, channel=11, capture_filename="c693698_Sniffer",
                                        beacon_stop=0)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_hidden_ssid_aput_beacon()
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.raspi_sta_assoc_to_dut_ap(hidden_ssid=1)
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_hidden_ssid_aput_beacon()
        ap_dut_obj.sniffer_capture_start()
        wifi_dut.interfaces.wifi.disconnect_ap_client(
            client_mac=ap_dut_obj.dut_add_dict['rasp_mac_address'], deauth_option="deauth_client_unspecified")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_hidden_ssid_aput_beacon()

    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,

    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11
                               }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.test_src_map_id('C693696')
def test_wifi_sdk_check_http_server_with_sl_net_init_denit_with_udp_tx_traffic_c693696(wifi_dut, wifi_sniffer,
                                                                                       sl_collections,
                                                                                       wifi_clients,
                                                                                       utf_constants,
                                                                                       sniffer_filter,
                                                                                       wifi_access_point):
    try:
        ap_dut_obj = AP11nParamsEnabled(wifi_dut=wifi_dut, wifi_clients=wifi_clients, wifi_sniffer=wifi_sniffer,
                                        sl_collections=sl_collections, utf_constants=utf_constants,no_of_clients= 1,
                                        sniffer_filter=sniffer_filter, wifi_access_point=wifi_access_point,
                                        testcase_no=693687, channel=11, capture_filename="c693696_Sniffer",
                                        beacon_stop=1)
        ap_dut_obj.sniffer_capture_start()
        ap_dut_obj.aput_start()
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_dut_obj.check_beacons_from_aput()
        ap_dut_obj.aput_client_connection()
        ''' Need to add HTTP Server Code '''
        ap_dut_obj.check_beacons_from_aput()
        ''' sl net_down api'''
        ap_dut_obj.sniffer_capture_start()
        ''' sl_netup api '''
        ap_dut_obj.aput_client_connection()
        ''' Need to add HTTP Server Code'''
        ap_dut_obj.check_beacons_from_aput()



    except Exception as Ex:
        logger().info(f"Exception Block")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Finally Block")
        wifi_dut.interfaces.wifi.stop_ap()
