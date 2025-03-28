from utf.utils.logger import get_logger
import pytest
import string
import time
from retry import retry
from utf.utils.stopwatch import Stopwatch
from random import randint
import ipaddress
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xPowerSaveModes,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xOperatingMode,
    Si91xExtCustomFeatureBitMap,
    Si91xJoinFeatureBitMap,
    Si91xMqttQos,
)
from utf.utils import print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.iperf.iperf_utils import ping
from threading import Thread
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers




def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


"""
     Setup Requirement:

        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)  

     Test Steps:

        1. Configure the DUT in 2G.
        2. Association of Third party AP's
        3. Configure the IPv6 addresses.
        4. Ping to the specified IPv6 address.
        5. Validate the Sniffer Checks.

     Authors: 
      - Swathi Chinthala 
"""
import ipaddress
import random


def random_ipv6_addr(subnet):
    network = ipaddress.ip_network(subnet)
    max_value = int(network.network_address) + network.num_addresses - 1
    random_ip = ipaddress.IPv6Address(random.randint(int(network.network_address), max_value))
    return str(random_ip)



class IperfThraed(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None, wifi_client=None,
                 test_id=None,
                 traffic_type=None, protocol=None, net_perf_client=None, timeout=60,
                 device_ip=None, remote_ip=None, ip_version=4):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.ip_version = ip_version
        self.device_ip = device_ip
        self.remote_ip = remote_ip

    def run_traffic(self):
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=self.device_ip,
            host_ip=self.remote_ip,
            timeout=self.timeout,
            traffic_type=self.traffic_type,
            ip_version=self.ip_version,
            buffer_size_tcp=1380,
            buffer_size_udp=1390,
            async_socket=0
        )

    def run(self):
        self.run_traffic()


class SocketDataTransfer(ThreadBase):
    def __init__(self, wifi_dut, remote_socket, utf_constants, dut_ip=None, data=None, interval=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.remote_socket = remote_socket
        self.utf_constants = utf_constants
        self.dut_ip = dut_ip
        self.data = data
        self.interval = interval

    def run_tcp_traffic(self):
        logger().info("Starting TCP server socket remotely")
        local_port = randint(6000, 6100)
        # self.remote_socket.interfaces.socket.interface = "wlan0"
        logger().info("Starting TCP Server socket at remote device")
        self.remote_socket.interfaces.socket.start_server(port=local_port)
        server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = self.remote_socket.interfaces.socket.server_port

        logger().info(f"DUT opens tcp client socket")
        tcp_socket_id = self.wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        bind_response = self.wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id, device_ip=self.dut_ip,
                                                      server_port=server_port,
                                                      timeout=5)
        logger().info(f"Bind socket successfully: {bind_response}")

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=server_ip,
                                                          server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        sw = Stopwatch()
        packets = 0
        while sw.elapsed_sec < 60:
            logger().info("DUT Sending Data packets")
            bytes_sent = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data=self.data, timeout=30)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
            logger().info("Setting TCP socket receive timeout in remote server")
            self.remote_socket.interfaces.socket.set_recv_timeout(socket_type=0)
            recv_data = self.remote_socket.interfaces.socket.recv_data_tcp(data_size=len(self.data))
            logger().info(f"data received : {recv_data}")
            packets = packets + 1
            logger().info(f"total packets received at the remote socket: {packets}")
            logger().info(f"adding time interval between packets: {self.interval}")
            time.sleep(self.interval)

        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=tcp_socket_id)
        self.remote_socket.interfaces.socket.stop()


    def run_tcp_rx_traffic(self):

        local_port = randint(6000, 6100)
        logger().info("Starting TCP Server socket at remote device")
        sock = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET6", stream_type="SOCK_STREAM",
                                                         protocol="IPPROTO_TCP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.dut_ip,
                                           server_port=local_port, asynch=0, ip_version=6)
        self.wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=0)
        ThreadBase.call_functions_simultaneously(
            [
                (self.wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 0, 6),
                (self.remote_socket.interfaces.socket.connect_client_tcp, self.dut_ip, local_port, None, None, 6),
            ],
            timeout=10,
        )
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            self.remote_socket.interfaces.socket.send_data_tcp(tx_buffer)
            time.sleep(self.interval)
            buffer_rx = self.wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock) + 1, timeout=30)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "


    def run_udp_traffic(self):
        local_port = randint(5001, 6000)
        logger().info("Starting UDP server socket at remote device")
        self.remote_socket.interfaces.socket.interface = "wlan0"
        self.remote_socket.interfaces.socket.start_server(socket_type=1)  # 0-TCP, 1-UDP
        server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = self.remote_socket.interfaces.socket.server_port
        logger().info(f"DUT opens tcp client socket")
        udp_socket_id = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_DGRAM",
                                                             protocol="IPPROTO_UDP")
        logger().info(f"Socket open successfully : {udp_socket_id}")
        logger().info("Initiating socket bind from DUT")
        self.wifi_dut.interfaces.wifi.bind(udp_socket_id, device_ip=self.dut_ip, server_port=local_port)
        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(udp_socket_id, server_ip=server_ip, server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        time.sleep(3)
        for packets in range(20):
            logger().info("DUT Sending Data packets")
            bytes_sent = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=udp_socket_id, data=self.data, timeout=30)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
            logger().info("Setting UDP socket receive timeout in remote server")
            self.remote_socket.interfaces.socket.set_recv_timeout(use_client_socket=True, socket_type=1)
            recv_data, address = self.remote_socket.interfaces.socket.recv_data_udp(data_size=len(self.data))
            logger().info(f"data received : {recv_data}")
            packets = packets + 1
            logger().info(f"total packets received at the remote socket: {packets}")
        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=udp_socket_id)
        self.remote_socket.interfaces.socket.stop()





class WLanConThread(ThreadBase):
    """
    Thread class for WLAN operations.
    """
    client_info, dut_info = {"mac_address": None, "ip_address": None}, {"mac_address": None, "ip_address": None}

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None, wifi_clients=None,
                 test_id=None, test_type=None, ping_count=10, remote_wiseconnect3=None, wifi_client=None,
                 ipv6_addr_type="global", switch=None, listen_interval=False,
                 set_power_save=False, traffic_type=None, protocol=None, net_perf_client=None, timeout=60,
                 ping_from="remote", remote_type="raspi", static_ipv6=None):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.wifi_clients = wifi_clients
        self.test_id = test_id
        self.ping_count = ping_count
        self.test_type = test_type
        self.ipv6_addr_type = ipv6_addr_type
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.ip_version = 6
        self.ssid = "Concurent_AP"
        self.security = "WPA2"
        self.password = "Automation@123"
        self.channel = "11"
        self.dtim_count = "3"
        self.beacon_interval = "100"
        self.no_of_clients = 1
        self.leave = False
        self.set_power_save = set_power_save
        self.listen_interval = listen_interval
        self.remote_type = remote_type
        self.ping_from = ping_from
        self.static_ipv6 = static_ipv6

        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

        self.remote_ipv6 = None
        self.remote_ipv4 = None
        self.dut_add_dict = None

    def enable_listen_interval_based_power_save(self):
        self.remote_wiseconnect3.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                         Si91xJoinFeatureBitMap.ListenIntervalFromJoin)

    def run_traffic(self, device_ip=None, remote_ip=None, ip_version=4):

        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=device_ip,
            host_ip=remote_ip,
            timeout=self.timeout,
            traffic_type=self.traffic_type,
            ip_version=ip_version,
            async_socket=0
        )

    @staticmethod
    def print_throughput(iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run_traffic_btwn_two_clients(self, net_perf_client, secondary_net_perf_client, server_ip, client_ip, protocol):
        net_perf_client.interfaces.net_perf.init_server(host_ip=client_ip, device_ip=server_ip, protocol=protocol,
                                                        host_role=IperfConstants.SERVER_MODE)
        net_perf_client.interfaces.net_perf.start()
        time.sleep(2)

        # preparing iperf client with secondary raspi
        secondary_net_perf_client.interfaces.net_perf.init_client(host_ip=client_ip, device_ip=server_ip,
                                                                  protocol=protocol,
                                                                  host_role=IperfConstants.CLIENT_MODE)
        secondary_net_perf_client.interfaces.net_perf.start()

        # waiting till time out for iperf client send data to iperf server
        time.sleep(net_perf_client.interfaces.net_perf.client_timeout)
        tp_server = net_perf_client.interfaces.net_perf.process_output()
        secondary_net_perf_client.interfaces.net_perf.clean_files()
        assert tp_server is not None
        self.print_throughput(tp_server)

    def ping(self, ip_address=None, ping_from="remote", ping_count=10, ip_version="ipv4"):
        """
        Ping the given IP address.
        """
        if ping_from == "remote":
            status = self.sl_collections.ping(device_ip=ip_address, ping_count=ping_count, retry_count=3)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if ping_from == "dut":
            self.wifi_dut.interfaces.wifi.ping(server_ip=ip_address, ip_version=ip_version, ping_size=64,
                                               num_ping_attempts=10)

    def connect_disconnect_raspi_clients(self):
            if self.clients_connected:
                logger().info(
                    f"********* Initiating 3rd party clients disconnect from DUT-AP' *********")
                for client in self.wifi_clients:
                    logger().info(f"len of wifi_clients: {len(self.wifi_clients)}")
                    client.interfaces.wifi.leave()
                self.clients_connected = False

    def raspi_client_leave(self):
        for i in range(self.no_of_clients):
            self.wifi_dut.interfaces.wifi.disconnect_ap_client(
                client_mac=self.dut_add_dict[f'client{i + 1}_mac'], deauth_option="deauth_client_unspecified")

    @staticmethod
    @retry(Exception, delay=15, tries=3)
    def ping_from_wifi_client(wifi_client, dest_ip, ping_count=10):
        logger().info(f"Initiating wlan ping from client '{wifi_client.name}' to destination_ip:'{dest_ip}'")
        for count in range(3):
            try:
                rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ping -c {ping_count} {dest_ip}")
                assert rc == 0
                logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                return rc == 0
            except:
                time.sleep(10)

    def assign_static_ip_to_ap(self):
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.dut_add_dict['dut_ap_ipv4'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ap_ipv4']}")
        self.static_ipv6 = random_ipv6_addr("1280:2300:133c:1341::/64")
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30, ip_version="ipv6", vid=1,
                                                           static_ipv6_address=self.static_ipv6,
                                                           ipv6_gw_address=self.static_ipv6)
        self.dut_add_dict['dut_ap_ipv6'] = self.static_ipv6

    def set_static_ip_clients(self):
        self.wifi_clients[0].interfaces.wifi.config['ip_address'] = "192.168.100.80"
        self.wifi_clients[1].interfaces.wifi.config['ip_address'] = "192.168.100.81"

        for i in range(len(self.wifi_clients)):
            self.wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
            self.wifi_clients[i].interfaces.wifi.configure_virtual_ip_address()
            sta_ipv6 = random_ipv6_addr("1280:2300:133c:1341::/64")
            self.wifi_clients[i].interfaces.wifi.config['ip_address6'] = sta_ipv6
            self.wifi_clients[i].interfaces.wifi.configure_virtual_ipv6_address()

        status = self.ping_from_wifi_client(self.wifi_clients[0], self.wifi_clients[1].interfaces.wifi.config['ip_address'],
                                            ping_count=30)
        assert status, f"RASPI-STA1 failed to ping to RASPI-STA2"


    def create_ap_connect_remote_clients(self, count=3):
        self.assign_static_ip_to_ap()
        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.password,
                                               channel=self.channel,
                                               dtim_beacon_count=self.dtim_count,
                                               beacon_interval=self.beacon_interval)

        for i in range(len(self.wifi_clients)):
            self.wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            # logger().info(f"********* Dut as AP IP **********: {self.ip_dict['dut_ip']}")
            for retry_count in range(count):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{self.wifi_clients[i].name}' to DUT")
                    self.dut_add_dict[f'client{i + 1}_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    self.dut_add_dict[f'client{i + 1}_mac'] = self.wifi_clients[i].interfaces.wifi.get_mac_address()
                    logger().info(f"Client{i + 1}_ip: {self.dut_add_dict[f'client{i + 1}_ip']}")
                    rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {self.ping_count} {self.dut_add_dict['dut_ap_ipv4']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except Exception as error:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT:\n{error}...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        self.clients_connected = True

    def join_to_remote_sdk_device(self):

        self.assign_static_ip_to_ap()
        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.password,
                                               channel=self.channel,
                                               dtim_beacon_count=self.dtim_count,
                                               beacon_interval=self.beacon_interval)
        if self.listen_interval:
            self.enable_listen_interval_based_power_save()
        self.remote_wiseconnect3.interfaces.wifi.join(ssid=self.ssid,
                                                      security=self.security.lower(),
                                                      passphrase=self.password,
                                                      channel=self.channel, timeout=60)
        ip_config = self.remote_wiseconnect3.interfaces.wifi.start_ip(timeout=60, ip_version="ipv4")
        device_ipv4 = self.remote_wiseconnect3.interfaces.wifi.get_device_ip(ip_config)

        ip_config = self.remote_wiseconnect3.interfaces.wifi.start_ip(timeout=60, ip_version="ipv6")
        # device_ipv6 = self.remote_wiseconnect3.interfaces.wifi.get_device_ip(ip_config)

        self.dut_add_dict['remote_sta_ipv6'] = ip_config[1]
        self.dut_add_dict['remote_sta_ipv4'] = device_ipv4

        self.remote_wiseconnect3.interfaces.wifi.ping(server_ip=self.dut_add_dict['dut_ap_ipv4'],
                                                      num_ping_attempts=self.ping_count,
                                                      ping_timeout=10, ip_version='ipv4', ping_size=64)
        self.remote_wiseconnect3.interfaces.wifi.ping(server_ip=self.dut_add_dict['dut_ap_ipv6'],
                                                      num_ping_attempts=self.ping_count,
                                                      ping_timeout=10, ip_version='ipv6', ping_size=64)

        time.sleep(2)
        if self.set_power_save:
            self.enable_power_save()

    def enable_power_save(self):
        if self.power_save:
            self.remote_wiseconnect3.interfaces.wifi.set_performance_profile('power_save_low_latency')

    def join_to_ap(self):
        self.dut_add_dict = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     power_save=False, retry_count=3,
                                                                     ping_before_power_save=False,
                                                                     ping_after_power_save=False,
                                                                     )
        self.dut_add_dict['ap_mac_address'] = self.wifi_access_point.interfaces.wifi.bssid

        if self.static_ipv6:
            ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30, ip_version="ipv6", vid=0,
                                                               static_ipv6_address=self.static_ipv6,
                                                               ipv6_gw_address=self.static_ipv6, )
        else:
            ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=1,
                                                                    ip_version="ipv6")

            assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
        self.dut_add_dict['dut_sta_ipv6_global'] = ip_config[1]
        self.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]
        logger().info(f"DUT MAC ADDRESS :  {self.dut_add_dict['dut_mac_address']}\n"
                      f"DUT IPV4 ADDRESS : {self.dut_add_dict['device_ip']}\nDUT IPV6 GLOBAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_global']}\n"
                      f"DUT IPV6 LINK LOCAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_link']}\n")

        self.dut_add_dict['remote_ap_ipv6'] = self.wifi_client.interfaces.wifi.get_ip_address(version=6,
                                                                                              addr_type=self.ipv6_addr_type)
        logger().info(f"remote_ap_ipv6: {self.dut_add_dict['remote_ap_ipv6']}")
        self.dut_add_dict['remote_ap_ipv6'] = ipaddress.ip_address(self.dut_add_dict['remote_ap_ipv6'])
        self.dut_add_dict['remote_ap_ipv4'] = self.wifi_client.interfaces.wifi.get_ip_address(version=4)
        logger().info(f"remote_ap_ipv4: {self.dut_add_dict['remote_ap_ipv4']}")

    def check_ping_from_remote_to_dut_sta(self):
        self.ping(ip_address=self.dut_add_dict['device_ip'], ping_from="remote", ping_count=self.ping_count,
                  ip_version="ipv4")
        if self.ipv6_addr_type == "link":
            interface = self.wifi_client.interfaces.wifi.config["interface"]
            dut_addr = f"{self.dut_add_dict['dut_sta_ipv6_link']}%{interface}"
        else:
            dut_addr = self.dut_add_dict['dut_sta_ipv6_global']
        self.ping(ip_address=dut_addr, ping_from="remote", ping_count=self.ping_count,
                  ip_version="ipv6")

    def check_ping_from_dut_sta_to_remote(self):
        self.ping(ip_address=self.dut_add_dict['remote_ap_ipv4'], ping_from="dut", ping_count=self.ping_count,
                  ip_version="ipv4")
        self.ping(ip_address=self.dut_add_dict['remote_ap_ipv6'], ping_from="dut", ping_count=self.ping_count,
                  ip_version="ipv6")

    def check_ping_from_remote_to_dut_sta(self):
        self.ping(ip_address=self.dut_add_dict['device_ip'], ping_from="remote", ping_count=self.ping_count,
                  ip_version="ipv4")
        self.ping(ip_address=self.dut_add_dict['dut_sta_ipv6_global'], ping_from="remote", ping_count=self.ping_count,
                  ip_version="ipv6")

    def check_ping_from_dut_ap_to_remote(self):
        self.ping(ip_address=self.dut_add_dict['remote_sta_ipv4'], ping_from="dut", ping_count=self.ping_count,
                  ip_version="ipv4")
        self.ping(ip_address=self.dut_add_dict['remote_sta_ipv6'], ping_from="dut", ping_count=self.ping_count,
                  ip_version="ipv6")

    def check_ping_from_remote_to_dut_ap(self):
        time.sleep(2)
        self.remote_wiseconnect3.interfaces.wifi.ping(server_ip=self.dut_add_dict['dut_ap_ipv4'],
                                                      num_ping_attempts=self.ping_count,
                                                      ping_timeout=10, ip_version='ipv4', ping_size=64)
        self.remote_wiseconnect3.interfaces.wifi.ping(server_ip=self.dut_add_dict['dut_ap_ipv6'],
                                                      num_ping_attempts=self.ping_count,
                                                      ping_timeout=10, ip_version='ipv6', ping_size=64)

    def run(self):

        """
        Runs the thread.
        """

        if self.remote_type == "raspi":
            self.join_to_ap()
            self.create_ap_connect_remote_clients()

            if self.ping_from == "dut":
                self.check_ping_from_dut_sta_to_remote()
            else:
                self.check_ping_from_remote_to_dut_sta()
        else:
            self.join_to_ap()
            self.join_to_remote_sdk_device()
            if self.ping_from == "dut":
                self.check_ping_from_dut_sta_to_remote()
            else:
                self.check_ping_from_remote_to_dut_sta()


def wifi_dut_marker(ext_custom_bit=0, thread_count=1, tcp_feat_bit=0, ext_tcp_feat_bit=0, ca_cert=None):
    config = {
        "thread_config": {"wifi": {"count": thread_count, "stack_len": 4096}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | tcp_feat_bit,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | ext_custom_bit,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | ext_tcp_feat_bit,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    return pytest.mark.config("wifi_dut", wifi=config)


def remote_wiseconnect3_config():
    return {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "Concurent_AP", "passphrase": "Automation@123", "channel": 11
    }


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_wifi_melco_sdk_ipv4_ipv6_assignment_C557352(wifi_dut, wifi_access_point,
                                                     wifi_sniffer,
                                                     sl_collections, request,
                                                     sniffer_filter,
                                                     utf_constants,
                                                     wifi_clients,
                                                     wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        wifi_clients = wifi_clients[:2]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wlan_obj.connect_disconnect_raspi_clients()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
def test_wifi_melco_sdk_ipv4_tcp_tx_C557353(wifi_dut, wifi_access_point,
                                            wifi_sniffer,
                                            sl_collections,
                                            request,
                                            sniffer_filter,
                                            utf_constants,
                                            wifi_client, wifi_clients, net_perf_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4. Enable wlan and bt power save mode in dut after the connection
        5. Ping from remote to DUT IPV6 address
        6. Run TCP TX on IPV4

    """
    test_name = request.node.name
    try:
        wifi_clients = wifi_clients[:2]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client, protocol="TCP",
                                 traffic_type="TX",
                                 net_perf_client=net_perf_client,
                                 wifi_clients=wifi_clients,
                                 remote_type="raspi"

                                 )
        wlan_obj.join_to_ap()
        wlan_obj.create_ap_connect_remote_clients()
        wlan_obj.check_ping_from_remote_to_dut_sta()
        wlan_obj.run_traffic(device_ip=wlan_obj.dut_add_dict['device_ip'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv4'],
                             ip_version=4)
        wlan_obj.connect_disconnect_raspi_clients()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()




@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        2: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        3: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
def test_wifi_melco_sdk_ipv4_tcp_tx_C557359(wifi_dut, wifi_access_point,
                                            wifi_sniffer,
                                            sl_collections,
                                            request,
                                            sniffer_filter,
                                            utf_constants,
                                            wifi_client, wifi_clients, net_perf_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4. Enable wlan and bt power save mode in dut after the connection
        5. Ping from remote to DUT IPV6 address
        6. Run TCP TX on IPV4

    """
    test_name = request.node.name
    try:
        wifi_clients = wifi_clients[:4]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client, protocol="TCP",
                                 traffic_type="TX",
                                 net_perf_client=net_perf_client,
                                 wifi_clients=wifi_clients,
                                 remote_type="raspi"

                                 )
        wlan_obj.join_to_ap()
        wlan_obj.create_ap_connect_remote_clients()
        wlan_obj.check_ping_from_remote_to_dut_sta()
        logger().info("ping from STA1 TO STA2")
        client2_ip = wlan_obj.dut_add_dict['client2_ip']
        status = wlan_obj.ping_from_wifi_client(wifi_clients[0], client2_ip)
        assert status, f"RASPI-STA1 failed to ping to RASPI-STA2"
        wlan_obj.run_traffic(device_ip=wlan_obj.dut_add_dict['device_ip'],
                             remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv4'],
                             ip_version=4)
        wlan_obj.connect_disconnect_raspi_clients()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.HTTPClient)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
def test_wifi_melco_sdk_http_client_ipv4_ipv6_C557360(wifi_dut, wifi_access_point,
                                                      wifi_sniffer,
                                                      sl_collections, request,
                                                      sniffer_filter,
                                                      utf_constants,
                                                      wifi_clients, http_server,
                                                      wifi_client,
                                                      http_client, index_path):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    http_client_status = ""
    test_name = request.node.name
    try:
        wifi_clients = wifi_clients[:2]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("ping from STA1 TO STA2")
        client2_ip = wlan_obj.dut_add_dict['client2_ip']
        status = wlan_obj.ping_from_wifi_client(wifi_clients[0], client2_ip)
        assert status, f"RASPI-STA1 failed to ping to RASPI-STA2"
        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init()

        wifi_dut.interfaces.wifi.http_get(http_server.interfaces.http,
                                          resource_path=index_path,
                                          server_port=80)
        time.sleep(5)
        wifi_dut.interfaces.wifi.http_post(http_server.interfaces.http,
                                           resource_path="cgi-bin/cgi_example.py",
                                           post_data=''.join(random.choices(
                                               string.ascii_uppercase + string.digits, k=30)),
                                           server_port=80)
        time.sleep(5)

        wifi_dut.interfaces.wifi.http_put(server=http_server.interfaces.http,
                                          resource_path="cgi-bin/cgi_example.py",
                                          server_port=80)
        time.sleep(5)
        wifi_dut.interfaces.wifi.http_client_deinit()
        http_client_status = False
        wlan_obj.connect_disconnect_raspi_clients()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        if http_client_status:
            wifi_dut.interfaces.wifi.http_client_deinit()



@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 )
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
def test_wifi_melco_sdk_https_client_ipv4_ipv6_C557361(wifi_dut, wifi_access_point,
                                                       wifi_sniffer,
                                                       sl_collections, request,
                                                       sniffer_filter,
                                                       utf_constants,
                                                       wifi_clients, wifi_client, http_server,
                                                       http_client, index_path):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        wifi_clients = wifi_clients[:2]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("ping from STA1 TO STA2")
        client2_ip = wlan_obj.dut_add_dict['client2_ip']
        status = wlan_obj.ping_from_wifi_client(wifi_clients[0], client2_ip)
        assert status, f"RASPI-STA1 failed to ping to RASPI-STA2"
        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        server_ip = wlan_obj.dut_add_dict['remote_ap_ipv4']
        remote_ipv6 = wlan_obj.dut_add_dict['remote_ap_ipv6']
        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.wifi.http_client_init(https_enable=True, ip_version='ipv6')
        wifi_dut.interfaces.wifi.http_get(http_server.interfaces.http,
                                               resource_path=index_path,
                                               server_port=443, server_ip=f'"{remote_ipv6}"')
        time.sleep(5)
        wifi_dut.interfaces.wifi.http_post(http_server.interfaces.http,
                                                resource_path="cgi-bin/cgi_example.py",
                                                post_data=''.join(random.choices(
                                                    string.ascii_uppercase + string.digits, k=30)),
                                                server_port=443, server_ip=f'"{remote_ipv6}"')

        wifi_dut.interfaces.wifi.http_put(server=http_server.interfaces.http, resource_path="cgi-bin/cgi_example.py",
                                          server_ip=f'"{remote_ipv6}"', server_port=443)

        time.sleep(10)
        wifi_dut.interfaces.wifi.http_client_deinit()
        wlan_obj.connect_disconnect_raspi_clients()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker(ext_tcp_feat_bit=Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature, tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])

@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.config("secondary_net_perf_client", net_perf={"device": {"TCP": {"port": 5201, "data_len": 1460},
                                                                      "UDP": {"port": 5202, "data_len": 1460}}})

def test_wifi_melco_sdk_embedded_mqtt_ssl_ipv4_ipv6_C557363(wifi_dut, wifi_access_point,
                                                      wifi_sniffer,
                                                      sl_collections, request,
                                                      sniffer_filter,
                                                      utf_constants,
                                                      wifi_clients,
                                                      wifi_client,
                                                      mqtt_server,
                                                      mqtt_client,
                                                      net_perf_client,
                                                      secondary_net_perf_client,
                                                      protocol
                                                    ):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        mqtt_client.interfaces.mqtt.disable_certificate_verification = True
        wifi_clients = wifi_clients[:2]
        ping_count = utf_constants.get("ping_count")
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        topic = "test_topic_mqtt"
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        # logger().info("ping from STA1 TO STA2")
        # client2_ip = wlan_obj.dut_add_dict['client2_ip']
        # status = wlan_obj.ping_from_wifi_client(wifi_clients[0], client2_ip)
        # assert status, f"RASPI-STA1 failed to ping to RASPI-STA2"

        server_ip = wlan_obj.dut_add_dict['client1_ip']
        client_ip = wlan_obj.dut_add_dict['client2_ip']

        iperf_thread = Thread(target=wlan_obj.run_traffic_btwn_two_clients,
                              args=(net_perf_client, secondary_net_perf_client, server_ip, client_ip, protocol))
        iperf_thread.start()

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi

        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client",
                                                                        server_port=8883, qos=1,
                                                                        is_connection_encrypted=True)
        logger().info("DUT connects to MQTT server")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info("MQTT Client connects to MQTT server")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(3)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        time.sleep(3)
        logger().info("DUT publishes message over the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1, timeout=30)
        time.sleep(5)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"
        logger().info("MQTT messages validated successfully\n\n")

        logger().info("Unsubscribing from the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)

        iperf_thread.join()

        wlan_obj.connect_disconnect_raspi_clients()

        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_wifi_melco_sdk_ipv4_tcp_tx_5s_int_ipv6_ping_C557367(wifi_dut, wifi_access_point,
                                                             wifi_sniffer,
                                                             sl_collections, request,
                                                             sniffer_filter,
                                                             utf_constants,
                                                             wifi_clients,
                                                             wifi_client,
                                                             remote_socket):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        wifi_clients = wifi_clients[:2]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        socket_obj = SocketDataTransfer(wifi_dut, remote_socket, utf_constants,
                                        dut_ip=wlan_obj.dut_add_dict['device_ip'], data="Thisisfromtcpclient",
                                        interval=5)
        socket_obj.run_tcp_traffic()
        logger().info("ping from STA1 TO STA2")
        client2_ip = wlan_obj.dut_add_dict['client2_ip']
        for i in range(10):
            status = wlan_obj.ping_from_wifi_client(wifi_clients[0], client2_ip, ping_count=1)
            assert status, f"RASPI-STA1 failed to ping to RASPI-STA2"
            time.sleep(5)

        wlan_obj.connect_disconnect_raspi_clients()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()




@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_wifi_melco_sdk_ipv4_tcp_rx_5s_int_ipv6_ping_C557368(wifi_dut, wifi_access_point,
                                                             wifi_sniffer,
                                                             sl_collections, request,
                                                             sniffer_filter,
                                                             utf_constants,
                                                             wifi_clients,
                                                             wifi_client,
                                                             remote_socket):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        wifi_clients = wifi_clients[:2]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        socket_obj = SocketDataTransfer(wifi_dut, remote_socket, utf_constants,
                                        dut_ip=wlan_obj.dut_add_dict['dut_sta_ipv6_global'], data="Thisisfromtcpclient",
                                        interval=5)
        socket_obj.run_tcp_rx_traffic()
        logger().info("ping from STA1 TO STA2")
        client2_ip = wlan_obj.dut_add_dict['client2_ip']
        for i in range(10):
            status = wlan_obj.ping_from_wifi_client(wifi_clients[0], client2_ip, ping_count=1)
            assert status, f"RASPI-STA1 failed to ping to RASPI-STA2"
            time.sleep(5)

        wlan_obj.connect_disconnect_raspi_clients()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()




@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_wifi_melco_sdk_ipv4_tcp_tx_ipv6_ping_C557369(wifi_dut, wifi_access_point,
                                                             wifi_sniffer,
                                                             sl_collections, request,
                                                             sniffer_filter,
                                                             utf_constants,
                                                             wifi_clients,
                                                             wifi_client,
                                                             remote_socket):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        wifi_clients = wifi_clients[:2]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        socket_obj = SocketDataTransfer(wifi_dut, remote_socket, utf_constants,
                                        dut_ip=wlan_obj.dut_add_dict['device_ip'], data="Thisisfromtcpclient",
                                        interval=0)
        socket_obj.run_tcp_traffic()
        logger().info("ping from STA1 TO STA2")
        client2_ip = wlan_obj.dut_add_dict['client2_ip']
        status = wlan_obj.ping_from_wifi_client(wifi_clients[0], client2_ip, ping_count=30)
        assert status, f"RASPI-STA1 failed to ping to RASPI-STA2"

        wlan_obj.connect_disconnect_raspi_clients()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_wifi_melco_sdk_static_ipv4_ipv6_C557370(wifi_dut, wifi_access_point,
                                                 wifi_sniffer,
                                                 sl_collections, request,
                                                 sniffer_filter,
                                                 utf_constants,
                                                 wifi_clients,
                                                 wifi_client,
                                                 remote_socket):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        wifi_clients = wifi_clients[:2]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.set_static_ip_clients()

        logger().info("ping from STA1 TO STA2")
        client2_ip = wlan_obj.dut_add_dict['client2_ip']
        status = wlan_obj.ping_from_wifi_client(wifi_clients[0], client2_ip, ping_count=30)
        assert status, f"RASPI-STA1 failed to ping to RASPI-STA2"

        wlan_obj.connect_disconnect_raspi_clients()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()




@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "Concurent_AP",
            "passphrase": "Automation@123",
            "channel": 11,
        }
    }
)
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.skip()
def test_wifi_melco_sdk_ipv4_ipv6_ip_change_notificaton_C557364(wifi_dut, wifi_access_point,
                                                     wifi_sniffer,
                                                     sl_collections, request,
                                                     sniffer_filter,
                                                     utf_constants,
                                                     wifi_clients,
                                                     wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        wifi_clients = wifi_clients[:1]
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2",
                                                         dhcp_end="192.168.50.100",
                                                         dhcp_lease="120")
        time.sleep(60)
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")
        wifi_dut.interfaces.wifi.sl_net_init(mode="ap")

        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 wifi_clients=wifi_clients,
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.100", dhcp_end="192.168.50.200",
                                                         dhcp_lease="120")

        time.sleep(100)
        events = []
        for i in range(0, 3):
            time.sleep(20)
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events) >= 1:
                break
        assert len(events) >= 1, "TCP Remote terminate event not found"
        ip_change_notification = ""
        for event in events:
            if event.event_type == AsyncEventIdentifiers.IP_CHANGE_NOTIFICATION:
                ip_change_notification = event.event_data
        logger().info(f"*********{ip_change_notification}*************")
        assert ip_change_notification, f"unable to find ip_change_notification"
        logger().info("ip_change_notification event is received by DUT when range changed in AP")
        time.sleep(60)
        wlan_obj.connect_disconnect_raspi_clients()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



