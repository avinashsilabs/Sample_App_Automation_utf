import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xOperatingMode, Si91xPowerSaveModes, \
    Si91xPowerSaveProcedureTypes, Si91xAwsQos
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf.interfaces.shell.ssh_shell import SSHShell
from utf.utils.logger import get_logger
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from random import randint
import random
import string
import threading
from threading import Thread
from utf.interfaces.wifi import SecurityMode
import subprocess
import re
from retry import retry
from utf.utils import get_tls_certificate_dir
from AWSIoTPythonSDK.core.protocol.internal.clients import ClientStatus


def logger():
    return get_logger(__name__)


def text_generator(size=2000):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


""" Test Steps:
        1. Configure the DUT in Wlan for 2.4Gh with LWIP stack default timer enabled and validate the WLAN functionality.

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Sakshi Agrawal
"""

Map_security = {
    "OPEN": 0,
    "WPA": 1,
    "WPA2": 2,
    "WEP": 3,
    "WPAEnterprise": 4,
    "WPA2Enterprise": 5,
    "WPA_WPA2_MIXED": 6,
    "WPA3": 7,
    "WPA3_TRANSITION": 8,
    "WPA3Enterprise": 9,
    "WPA3_TRANSITION_ENTERPRISE": 10,
}


class UDPTXThread(ThreadBase):
    """This thread is responsible for TCP data transfer"""

    def __init__(self, wifi_dut=None, wifi_client=None, device_ip=None, protocol=None, net_perf_client=None,
                 remote_socket_factory=None, port=8001, no_of_pkts=1, data_transfer=True):
        super().__init__()
        self.thread_lock = threading.Lock()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.device_ip = device_ip
        self.protocol = protocol
        self.net_perf_client = net_perf_client
        self.port = port

    def run(self):
        transfer_type = 2  # UDP
        throughput_type = 2  # UDP TX
        pkt_size = 1460
        duration = 40
        timeout = duration + 5
        dut_ip = self.device_ip
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=dut_ip, protocol=self.protocol)
        self.net_perf_client.interfaces.net_perf.start()

        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=17,
                                            local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            local_ip=dut_ip, remote_ip=host_ip,
                                            remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            size=pkt_size, ttl=duration, throughput_type=throughput_type,
                                            timeout=timeout,
                                            host_tcp_ip_stack_enable=1)
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, f"throughput not Found"
        logger().info("\n ================ data transfer is successful ================= \n ")
        self.net_perf_client.interfaces.net_perf.iperf_process.stop(5)
        time.sleep(5)


class TCPTXThread(ThreadBase):
    """This thread is responsible for TCP data transfer"""

    def __init__(self, wifi_dut=None, wifi_client=None, device_ip=None, protocol=None, keepalive_timeout=0,
                 remote_socket_factory=None, port=5001, no_of_pkts=1, data_transfer=True, close=False):
        super().__init__()
        self.thread_lock = threading.Lock()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.device_ip = device_ip
        self.protocol = protocol
        self.keepalive_timeout = keepalive_timeout
        self.remote_socket_factory = remote_socket_factory
        self.client_socket = None
        self.server_socket = None
        self.no_of_pkts = no_of_pkts
        self.port = port
        self.data_transfer = data_transfer
        self.close = close

    def tx_data_transfer(self):
        data_length = 50
        sent_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=data_length))
        for i in range(self.no_of_pkts):
            logger().info(f"\n ****** Starting TCP TX Data Transfer from DUT to server at iteration {i + 1} \n ******")
            try:
                self.wifi_dut.interfaces.wifi.lwipSocketSend(socket_fd=self.client_socket, data=sent_data)
                received_data = (self.server_socket.recv_data_tcp(len(sent_data)))
                logger().info(f"\nReceived Data: {received_data}\n")
                assert (sent_data == received_data), f"Data mismatch in sent and received data"
            except Exception as e:
                logger().info(f"Socket Data Transfer Failed Within Duration")

        logger().info("\n ****** data transfer successful ****** \n")

    def run(self):
        local_port = self.port
        server_ip = self.wifi_client.interfaces.wifi.get_ip_address()

        self.server_socket = self.remote_socket_factory.interfaces.socket.create_socket()
        self.server_socket.start_server(port=local_port)
        logger().info(f"\n ****** TCP Server started successfully at port : {local_port}  ****** \n")

        self.client_socket = self.wifi_dut.interfaces.wifi.lwipSocketCreate(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                            protocol="IPPROTO_TCP")
        logger().info(f"\n ****** Socket open successfully : {self.client_socket} ****** \n")

        self.wifi_dut.interfaces.wifi.lwipSocketBind(socket_fd=self.client_socket, device_ip=self.device_ip,
                                                     server_port=local_port)

        if self.keepalive_timeout > 0:
            self.wifi_dut.interfaces.wifi.lwipSetSocketOpt(socket_fd=self.client_socket, option_level="SOL_SOCKET",
                                                           option_name="SO_KEEPALIVE", option_val=1)
            self.wifi_dut.interfaces.wifi.lwipSetSocketOpt(socket_fd=self.client_socket, option_level="IPPROTO_TCP",
                                                           option_name="TCP_KEEPALIVE",
                                                           option_val=self.keepalive_timeout * 1000)
            logger().info(f"\n ****** Keepalive timeout {self.keepalive_timeout} sec set successfully on DUT ******\n")

        connect_status = False
        for count in range(3):
            try:
                self.wifi_dut.interfaces.wifi.lwipSocketConnect(socket_fd=self.client_socket, server_ip=server_ip,
                                                                server_port=local_port)
                connect_status = True
                break
            except:
                logger().info(f"\n ****** Socket connection failed in DUT...retry_count:{count + 1} ****** \n")

        assert connect_status, "Socket connection failed in DUT after 3 attempts"
        logger().info("\n *********** Socket connection is successful ************ \n")

        if self.data_transfer:
            self.tx_data_transfer()

        if self.keepalive_timeout > 0:
            logger().info("Verifying keepalive functionality by waiting for timeout period...")
            time.sleep(self.keepalive_timeout * 3)
        if self.close:
            self.wifi_dut.interfaces.wifi.lwipSockClose(socket_fd=self.client_socket)
            logger().info(f"\n ****** Socket closed successfully in DUT ****** \n")


class TCPRXThread(ThreadBase):
    """This thread is responsible for TCP data reception (DUT as server)"""

    def __init__(self, wifi_dut=None, wifi_client=None, device_ip=None, protocol=None, keepalive_timeout=0,
                 remote_socket_factory=None, port=5002, no_of_pkts=1, data_transfer=True):
        super().__init__()
        self.thread_lock = threading.Lock()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.device_ip = device_ip
        self.protocol = protocol
        self.keepalive_timeout = keepalive_timeout
        self.remote_socket_factory = remote_socket_factory
        self.client_socket = None
        self.server_socket = None
        self.accepted_socket = None
        self.port = port
        self.no_of_pkts = no_of_pkts
        self.data_transfer = data_transfer

    def RX_data_transfer(self):
        self.no_of_pkts = 10
        data_length = 50
        sent_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=data_length))
        for i in range(self.no_of_pkts):
            logger().info(
                f"\n ****** Starting TCP RX Data Transfer from Client to DUT Server at iteration {i + 1} ****** \n")
            try:
                # Send data from remote client to DUT server
                self.client_socket.send_data_tcp(sent_data)

                # Receive data on DUT server
                received_data = self.wifi_dut.interfaces.wifi.lwipSocketReceive(socket_fd=self.accepted_socket)
                logger().info(f"\nDUT Server Received Data: {received_data}\n")
                assert (sent_data == received_data), f"Data mismatch in sent and received data"
            except Exception as e:
                logger().error(f"TCP RX Socket Data Transfer Failed: {e}")
                raise e

        logger().info("\n ****** TCP RX data transfer successful ****** \n")

    def run(self):
        server_port = self.port  # Different port than TCP TX

        # DUT acts as TCP server
        self.server_socket = self.wifi_dut.interfaces.wifi.lwipSocketCreate(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                            protocol="IPPROTO_TCP")
        logger().info(f"\n ****** TCP Server Socket created successfully : {self.server_socket} ****** \n")

        # Bind and listen on DUT
        self.wifi_dut.interfaces.wifi.lwipSocketBind(socket_fd=self.server_socket, device_ip=self.device_ip,
                                                     server_port=server_port)
        self.wifi_dut.interfaces.wifi.lwipSocketListen(socket_fd=self.server_socket, backlog=1)
        logger().info(f"\n ****** TCP Server listening on {self.device_ip}:{server_port} ****** \n")

        if self.keepalive_timeout > 0:
            self.wifi_dut.interfaces.wifi.lwipSetSocketOpt(socket_fd=self.server_socket, option_level="SOL_SOCKET",
                                                           option_name="SO_KEEPALIVE", option_val=1)
            self.wifi_dut.interfaces.wifi.lwipSetSocketOpt(socket_fd=self.server_socket, option_level="IPPROTO_TCP",
                                                           option_name="TCP_KEEPIDLE", option_val=30)
            logger().info(
                f"\n ****** Keepalive timeout {self.keepalive_timeout} sec set successfully on DUT server ******\n")

        # Remote client connects to DUT server
        self.client_socket = self.remote_socket_factory.interfaces.socket.create_socket()

        connect_status = False
        for count in range(3):
            try:
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (
                            self.wifi_dut.interfaces.wifi.lwipSocketAccept,
                            self.server_socket,
                        ),
                        (
                            self.client_socket.connect_client_tcp,
                            self.device_ip,
                            server_port,
                        ),
                    ],
                    timeout=10,
                )

                # Get the accepted socket descriptor from the result
                self.accepted_socket = result[0] if result else None
                self.accepted_socket = int(self.accepted_socket.decode().strip())
                connect_status = True
                break
            except:
                logger().info(f"\n ****** Socket connection failed in DUT...retry_count:{count + 1} ****** \n")
        assert connect_status, "Socket connection failed in DUT"
        logger().info(f"\n ****** Connection accepted on DUT server : {self.accepted_socket} ****** \n")

        if self.data_transfer:
            self.RX_data_transfer()

        if self.keepalive_timeout > 0:
            logger().info("Verifying keepalive functionality by waiting for timeout period...")
            time.sleep(self.keepalive_timeout * 3)


class WifiThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None,
                 capture_filename=None, test_case_no=None, power_save=True, leave=True, stop_capture=True,
                 wifi_client=None, ip_version='ipv4', ping_count=10):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.capture_filename = capture_filename
        self.test_case_no = test_case_no
        self.device_ip = None
        self.power_save = power_save
        self.wifi_client = wifi_client
        self.leave = leave
        self.stop_capture = stop_capture
        self.ip_version = ip_version
        self.ping_count = ping_count
        self.dut_addr = None
        self.ap_addr = None

    def clear_device_arp_cache(self):
        command = ['sudo', 'arp', '-d', self.device_ip]
        result = subprocess.run(command, capture_output=True)
        rc = result.returncode
        stdout = result.stdout.decode("utf-8")
        stderr = result.stderr.decode("utf-8")
        if rc != 0 or stderr:
            logger().info(f"{command} command exited with code {rc} with output:\n{stdout}\n{stderr}")
        else:
            logger().info(f"{command} command exited with code {rc} with output:\n{stdout}")

    def delta_between_dhcp_req_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff = []
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()

        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                time_diff.append(float(time_delta_from_previous_packet))

        logger().info(time_diff)
        filter_file.close()
        return time_diff

    def extract_nak_epoch_time(self, file_path):
        """Extract epoch time from NAK packet data in filter file"""
        epoch_times = []
        try:
            with open(file_path, "r") as file:
                lines = file.readlines()

            for line in lines:
                # Search for epoch time pattern directly
                if "Epoch Time:" in line:
                    epoch_match = re.search(r"Epoch Time:\s+([\d.]+)", line)
                    if epoch_match:
                        epoch_times.append(float(epoch_match.group(1)))

            logger().info(f"Extracted NAK epoch times: {epoch_times}")
            return epoch_times

        except FileNotFoundError:
            logger().error(f"File not found: {file_path}")
            return []
        except Exception as e:
            logger().error(f"Error extracting NAK epoch time: {e}")
            return []

    def run(self):

        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.capture_filename}.pcap"
        )
        self.dut_addr = self.wifi_dut.interfaces.wifi.get_mac_address()
        self.ap_addr = self.wifi_access_point.interfaces.wifi.bssid

        self.wifi_dut.interfaces.wifi.lwip_join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                timeout=60)
        ip_config = self.wifi_dut.interfaces.wifi.lwip_start_ip(timeout=60, ip_version=self.ip_version)

        if self.ip_version == 'ipv6':
            # For LWIP stack, only link-local address is implemented
            self.device_ip = ip_config[0]
            logger().info(f"IPv6 link-local address: {self.device_ip}")
        else:
            self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info(f"\n =========== DUT IP address is : {self.device_ip} =========== \n")
        time.sleep(15)
        logger().info("=========== pinging DUT before power save ===============")
        if self.ip_version == 'ipv6':
            status = self.sl_collections.ping_ipv6_link_local(device_ipv6=self.device_ip, interface='wlan0',
                                                              ping_count=10)
        else:
            status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=self.ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.power_save:
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                               psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        logger().info("=========== pinging DUT after power save ===============")
        if self.ip_version == 'ipv6':
            status = self.sl_collections.ping_ipv6_link_local(device_ipv6=self.device_ip, interface='wlan0',
                                                              ping_count=self.ping_count)
        else:
            status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=self.ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.test_case_no == 919291:
            logger().info(f"\n==========>>>>>>Waiting up to 300 seconds for dhcp renewal packets<<<<<<===========\n")
            time.sleep(300)

        if self.leave:
            self.wifi_dut.interfaces.wifi.leave()
            logger().info(f"Disconnection will issued after verification")

        if self.stop_capture:
            self.wifi_sniffer.interfaces.capture.stop_capture()


class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None, profile=None,
                 capture_filename=None, test_case_no=None, power_save=True, leave=True, stop_capture=True,
                 wifi_client=None, ip_version='ipv4'):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.dut_addr = None
        self.ap_addr = None
        self.sl_collections = sl_collections
        self.capture_filename = capture_filename
        self.test_case_no = test_case_no
        self.profile = profile
        self.device_ip = None
        self.power_save = power_save
        self.wifi_client = wifi_client
        self.leave = leave
        self.stop_capture = stop_capture
        self.ip_version = ip_version

    def delta_between_dhcp_req_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff = []
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()

        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                time_diff.append(float(time_delta_from_previous_packet))

        logger().info(time_diff)
        filter_file.close()
        return time_diff

    def run(self):
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.capture_filename}.pcap"
        )
        self.dut_addr = self.wifi_dut.interfaces.wifi.get_mac_address()
        self.ap_addr = self.wifi_access_point.interfaces.wifi.bssid

        self.wifi_dut.interfaces.wifi.sl_net_set_profile(
            ssid=self.profile["ssid"],
            security=Map_security[self.profile["security"]],
            credential_id=(1 if Map_security[self.profile["security"]] != 0 else 0),
            priority=1,
            profile_id=0,
            ip_type=self.ip_version,
            channel=self.profile["channel"],
            encryption=self.profile["encryption_type"],
        )
        self.wifi_dut.interfaces.wifi.sl_net_set_credential(credential=self.profile["passphrase"], cred_id=1)
        self.wifi_dut.interfaces.wifi.sl_net_up(mode="client")
        ip_config = self.wifi_dut.interfaces.wifi.display_device_ip_lwip(ip_version=self.ip_version)
        if self.ip_version == 'ipv6':
            # For LWIP stack, only link-local address is implemented
            self.device_ip = ip_config[0]
            logger().info(f"IPv6 link-local address: {self.device_ip}")
        else:
            self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info(f"\n =========== DUT IP address is : {self.device_ip} =========== \n")

        logger().info("=========== pinging DUT before power save ===============")
        if self.ip_version == 'ipv6':
            status = self.sl_collections.ping_ipv6_link_local(device_ipv6=self.device_ip, interface="wlan0",
                                                              ping_count=10)
        else:
            status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.power_save:
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                               psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        logger().info("=========== pinging DUT after power save ===============")
        if self.ip_version == 'ipv6':
            status = self.sl_collections.ping_ipv6_link_local(device_ipv6=self.device_ip, interface='wlan0',
                                                              ping_count=10)
        else:
            status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address(
            network_interface='wlan0', version=6, addr_type='link'
        )

        logger().info(f"\n ****** Host IP Address: {host_ip} after ping ****** \n")

        if self.test_case_no == 919174:
            logger().info(f"\n==========>>>>>>Waiting up to 900 seconds for dhcp renewal packets<<<<<<===========\n")
            time.sleep(900)

        if self.leave:
            self.wifi_dut.interfaces.wifi.leave()
            logger().info(f"Disconnection will issued after verification")

        if self.stop_capture:
            self.wifi_sniffer.interfaces.capture.stop_capture()


class AwsConnection(ThreadBase):
    """
    Class to connect, subscribe, publish data from DUT/Raspi to AWS server.
    """

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None, test_name=None,
                 aws_iot_client=None, client_id=None, messages=None, topic=None, qos=Si91xAwsQos.QOS1, port=8883,
                 negative_case=False,
                 test_case=None):
        super().__init__()
        self.client_id = None
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.test_case = test_case
        self.timeout = 120
        self.aws_iot_client = aws_iot_client
        self.messages = messages
        self.topic = topic
        self.qos = qos
        self.port = port
        self.client_id = client_id

    def mqtt_keep_alive_check(self, dut_mac_address, test_case_name):
        remote_capture_file = self.wifi_sniffer.interfaces.capture.remote_capture_file
        logger().info(f"capture file is:{remote_capture_file}")

        filter_files = "/tmp/filter_files"
        test_case = test_case_name
        filtered_file = f"{filter_files}/{test_case}_main_filter.pcap"
        self.wifi_sniffer.interfaces.capture.shell(
            f"sudo rm -rf {filter_files}; sudo mkdir {filter_files}; sudo chmod +777 {filter_files};"
        )
        filter1 = f'tshark -r {remote_capture_file} -Y "(wlan.addr eq {dut_mac_address})" -w {filtered_file}'
        logger().info("Creating filtered packets")
        self.wifi_sniffer.interfaces.capture.shell(filter1)

        logger().info("Getting the ping request and response")
        filter3 = (
            f'tshark -r {filtered_file} -Y "(wlan.addr eq {dut_mac_address}) && (mqtt.msgtype ==4 or mqtt.msgtype '
            f'== 12)" -Tfields -e "mqtt.msgtype" -e "frame.time" -e "frame.time_re'
            f'lative" > {filter_files}/mqtt_publish_ack_ping_req.txt'
        )
        self.wifi_sniffer.interfaces.capture.shell(filter3)
        if isinstance(self.wifi_sniffer.interfaces.capture.shell, SSHShell):
            with self.wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp_main:
                sftp_main.get(filtered_file, f"./reports/{test_case}_delta_filter.pcap")
                result_file = f"./reports/mqtt_publish_ack_ping_req.txt"
                sftp_main.get(
                    f"{filter_files}/mqtt_publish_ack_ping_req.txt", result_file
                )
                sftp_main.close()
        publish_ack = []
        ping_request = []
        with open(result_file) as f:
            for line in f:
                if int(line.split()[0]) == 4:
                    publish_ack.append(line.split()[-1])
                elif int(line.split()[0]) == 12:
                    ping_request.append(line.split()[-1])
        return publish_ack, ping_request

    def load_certificate(self, certificate):
        cert_file = str(get_tls_certificate_dir().joinpath(certificate))
        with open(cert_file) as f:
            cert_contents = f.read()
        size = len(cert_contents)
        logger().info(f"\nLoading  Certificate {certificate} ")
        buffer_size = (512 * (int(size / 512))) + 512  # buffer_size should be more than size
        address = self.wifi_dut.interfaces.wifi.allocate_memory(size=buffer_size)
        self.wifi_dut.interfaces.wifi.load_memory(
            address, size=size, write_content=cert_contents
        )
        return address, size

    @retry(Exception, delay=15, tries=5)
    def subscribe_from_dut(self, timeout=120):
        logger().info(f"DUT is Subscribing on topic '{self.topic}' and QOS:'{self.qos}'")
        self.wifi_dut.interfaces.wifi.aws_lwip_mqtt_subscribe_command_handler(topic=self.topic, qos_level=self.qos,
                                                                              timeout=timeout)

    @retry(Exception, delay=10, tries=5)
    def connect_to_aws_server_from_raspi(self):
        logger().info("Connecting to aws server from aws_iot_client")
        self.aws_iot_client.interfaces.aws_iot.aws_iot_connect()
        time.sleep(5)
        status = self.aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, "Connecting to AWS server from aws_iot_client is failed"

    @retry(Exception, delay=10, tries=3)
    def subscribe_from_raspi(self):
        logger().info(f"\n\n *** aws_iot_client is Subscribing on topic '{self.topic}' and QOS:'{self.qos}'*** \n\n")
        self.aws_iot_client.interfaces.aws_iot.received_messages.clear()
        self.aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(self.topic, qos=self.qos)
        status = self.aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, f"Subscribe on topic:'{self.topic}' is failed from aws_iot_client"

    @retry(Exception, delay=5, tries=5)
    def publish_from_raspi(self, messages):
        status = self.aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, f"Publish on topic:'{self.topic}' is failed from aws_iot_client"

        if isinstance(messages, list):
            for i, msg in enumerate(messages):
                logger().info(
                    f"\naws_iot_client publishing message{i + 1} on topic:'{self.topic}' \nQOS:'{self.qos}'"
                    f"\nMessage{i + 1} with length:'{len(msg)} bytes'\nMessage{i + 1} is:'{msg}'")
                self.aws_iot_client.interfaces.aws_iot.aws_iot_publish(self.topic, msg, qos=self.qos)
                time.sleep(5)
        else:
            self.aws_iot_client.interfaces.aws_iot.aws_iot_publish(self.topic, messages, qos=self.qos)

    @retry(Exception, delay=15, tries=1)
    def publish_from_dut(self, message, higher_data_len=0, negative_case=False):
        logger().info(f"\nDUT is publishing message on topic:'{self.topic}' \nQOS:'{self.qos}'")
        if higher_data_len > 0:
            address = self.wifi_dut.interfaces.wifi.allocate_memory(size=len(message))
            self.wifi_dut.interfaces.wifi.load_memory(address=address, size=len(message), write_content=message)
            result = self.wifi_dut.interfaces.wifi.aws_lwip_mqtt_publish_command_handler(topic=self.topic,
                                                                                         qos_level=self.qos,
                                                                                         msg_payload=message,
                                                                                         use_higher_data_len=higher_data_len,
                                                                                         data_buffer=address)
            self.wifi_dut.interfaces.wifi.memory_free(address)
        else:
            logger().info(f"\nDUT is publishing message on topic:'{topic}' \nQOS:'{qos}'")
            result = self.wifi_dut.interfaces.wifi.aws_lwip_mqtt_publish_command_handler(topic=self.topic,
                                                                                         qos_level=self.qos,
                                                                                         msg_payload=message)
        if negative_case:
            return result

    def receive_aws_messages_from_dut(self, retries=3, wait_time=3, expected_status=SLStatus.SL_STATUS_OK):
        for retry_count in range(retries):
            try:
                time.sleep(wait_time)
                yield_data = self.wifi_dut.interfaces.wifi.aws_lwip_mqtt_yield_command_handler(timeout_ms=5000)
                pattern = re.compile(r"Topic:\s*(?P<Topic>[^,]+),\s*Message:\s*(?P<Message>[^\r\n]+)", re.DOTALL)
                match = pattern.search(yield_data)
                if match:
                    topic = match.group("Topic")
                    message = match.group("Message")
                    logger().info(f"\n Received MQTT message on DUT - Topic: {topic}, Message: {message} \n")
                    return message
                else:
                    raise AssertionError("No MQTT message received on DUT")
            except Exception as err:
                logger().warning(f"Failed to receive published message in DUT\n{err}")
                if "0x1" in str(err):
                    self.wifi_dut.interfaces.wifi.is_dut_bad_state = True
                    raise
                time.sleep(5)

    def connect_to_aws_server_from_dut(self, timeout=120):
        ca_cert, ca_cert_size = self.load_certificate(certificate="start_field.pem")
        client_cert, client_cert_size = self.load_certificate(certificate="client-certificate.crt")
        client_key, client_key_size = self.load_certificate(certificate="private-key.key")
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False

        for attempt in range(3):
            try:
                logger().info(f"AWS connection attempt {attempt + 1}/3")
                self.wifi_dut.interfaces.wifi.aws_lwip_mqtt_init_command_handler(cacert=ca_cert,
                                                                                 cacert_length=ca_cert_size,
                                                                                 client_cert=client_cert,
                                                                                 client_cert_length=client_cert_size,
                                                                                 client_key=client_key,
                                                                                 client_key_length=client_key_size,
                                                                                 timeout=timeout)
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.aws_lwip_mqtt_connect_command_handler(client_id=self.client_id)
                logger().info(f"AWS connection successful on attempt {attempt + 1}")
                return True
            except Exception as e:
                logger().warning(f"AWS connection attempt {attempt + 1} failed: {e}")
                if attempt < 2:  # Not the last attempt
                    logger().info("Retrying AWS connection...")
                    time.sleep(10)  # Wait before retry
                else:
                    logger().error("All AWS connection attempts failed")
                    raise e


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
        "dhcp_lease": "120",
    },
)
@pytest.mark.test_src_map_id('C919174')
def test_wifi_sdk_dhcp_2_min_renewal_func_lwip_c919174(wifi_sniffer, wifi_access_point, wifi_dut,
                                                       request, sl_collections, sniffer_filter, wifi_client):
    """This test case verifies DHCP renewal time to 2 min renewal functionality in LWIP stack for 30 min duration using LWIP Stack"""
    capture_filename = request.node.name
    time_delta = 60
    packet_filter2 = '        DHCP: Request (3)'
    packet_filter3 = '        DHCP: Ack (5)'

    profile = {
        "ssid": "ssid_profile1",
        "channel": 6,
        "security": "OPEN",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    req_status = None
    ack_status = None
    wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                              test_case_no=919174, wifi_client=wifi_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        device_address = {'sa_addr': wlan_obj.dut_addr, 'da_addr': wlan_obj.ap_addr,
                          'wlan_addr': wlan_obj.dut_addr}
        filters_name = {1: 'power_mgmt_bit', 2: 'dhcp'}
        output_1 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                        device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT 1 = {output_1}\n')
        assert all(output_1.values()), 'Unable to find expected filter'

        filters_name_1 = {1: 'dhcp_renewal'}
        output_2 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter, device_address,
                                                                        filters_name=filters_name_1,
                                                                        packet_filter2=packet_filter2)
        logger().info(f'\n OUTPUT 2 = {output_2}\n')
        assert all(output_2.values()), 'Unable to find expected filter'
        dhcp_request_packets_time_delta_list = wlan_obj.delta_between_dhcp_req_packet()
        logger().info(f'DHCP ACK packet time delta list= {dhcp_request_packets_time_delta_list}')
        dhcp_request_packets_time_delta_list.pop(0)
        logger().info(f'DHCP Req packet time delta list after removing 0 = {dhcp_request_packets_time_delta_list}')

        filters_name_2 = {1: 'dhcp_ack'}
        device_address2 = {'sa_addr': wlan_obj.ap_addr, 'da_addr': wlan_obj.dut_addr, }
        output_3 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter, device_address2,
                                                                        filters_name=filters_name_2,
                                                                        packet_filter2=packet_filter3)
        logger().info(f'\n OUTPUT 3 = {output_3}\n')
        assert all(output_3.values()), 'Unable to find expected filter'
        dhcp_ack_packets_time_delta_list = wlan_obj.delta_between_dhcp_req_packet()
        logger().info(f'DHCP ACK packet time delta list= {dhcp_ack_packets_time_delta_list}')
        dhcp_ack_packets_time_delta_list.pop(0)
        logger().info(f'DHCP ACK packet time delta list after removing 0 = {dhcp_ack_packets_time_delta_list}')

        for time_diff in dhcp_request_packets_time_delta_list:
            print(int(time_diff))
            is_between = int(time_diff) in range(45, time_delta + 5)
            if is_between is False:
                logger().info(f"{is_between}")
                req_status = is_between
                break
            else:
                logger().info(f"{is_between}")
                req_status = is_between

        for time_diff in dhcp_ack_packets_time_delta_list:
            print(int(time_diff))
            is_between = int(time_diff) in range(45, time_delta + 5)
            if is_between is False:
                logger().info(f"{is_between}")
                ack_status = is_between
                break
            else:
                logger().info(f"{is_between}")
                ack_status = is_between

        if not req_status:
            logger().info("DHCP Request time not within range so looking for DHCP Ack time")
            assert ack_status, 'value is out of range so test case is failed'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCPIPBypass,
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
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C919180')
def test_wifi_sdk_tcp_open_send_close_socket_c919180(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client, protocol):
    """This test case Verifies the tcp client socket is open, send data,close functionality using LWIP Stack"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                                     wifi_client=wifi_client,
                                     test_case_no=919180, leave=False, stop_capture=False)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        tcp_thread = TCPTXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                 protocol=protocol,
                                 remote_socket_factory=remote_socket_factory, data_transfer=True, close=True)
        tcp_thread.start()
        tcp_thread.wait_for_exit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Disconnection will issued after verification")
        wifi_dut.interfaces.wifi.leave()

        device_address = {'sa_addr': wifi_thread.dut_addr, 'da_addr': wifi_thread.ap_addr,
                          'ta_addr': wifi_thread.dut_addr, 'ra_addr': wifi_thread.ap_addr}

        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'ps_poll',
                        4: 'dhcp_4_way_handshake_packets', 5: 'tcp_syn_with_syn_ack_with_ack'}

        output = sl_collections.sniffer_validation_for_packet_filters(
            wifi_sniffer, sniffer_filter, device_address, filters_name=filters_name)

        logger().info(f'\n OUTPUT 1 = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("\n ================== Closing all LWIP sockets ================== \n")
        wifi_dut.interfaces.wifi.lwip_close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCPIPBypass,
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
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C919181')
def test_wifi_sdk_verify_tcp_keep_alive_functionality_c919181(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client, protocol):
    """This test case Verifies the tcp keep alive functionality using LWIP Stack"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                                     wifi_client=wifi_client,
                                     test_case_no=919181, leave=False, stop_capture=False)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        tcp_thread = TCPTXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                 protocol=protocol,
                                 remote_socket_factory=remote_socket_factory, keepalive_timeout=30, no_of_pkts=10)
        tcp_thread.start()
        tcp_thread.wait_for_exit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Disconnection will issued after verification")
        wifi_dut.interfaces.wifi.leave()

        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, wifi_thread.dut_addr,
                                               wifi_thread.ap_addr, sniffer_filter)
        logger().info(f"Starting the Keep Alive Validation with duration {tcp_thread.keepalive_timeout} seconds")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wifi_thread.dut_addr, ra_addr=wifi_thread.ap_addr, filter_name="keep_alive")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], f"Keep alive packets not found in sniffer packets"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("\n ================== Closing all LWIP sockets ================== \n")
        wifi_dut.interfaces.wifi.lwip_close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCPIPBypass,
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
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C919183')
def test_wifi_sdk_tcp_tx_rx_simultaneously_c919183(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client, protocol):
    """This test case Verifies the tcp client socket is open, send TX and RX data,close functionality using LWIP Stack"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                                     wifi_client=wifi_client,
                                     test_case_no=919183, leave=False, stop_capture=False)

        wifi_thread.start()
        wifi_thread.wait_for_exit()
        tcp_tx_thread = TCPTXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                    protocol=protocol, remote_socket_factory=remote_socket_factory, no_of_pkts=100, close=True)
        tcp_rx_thread = TCPRXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                    protocol=protocol, remote_socket_factory=remote_socket_factory, no_of_pkts=100)
        tcp_tx_thread.start()
        tcp_rx_thread.start()
        tcp_tx_thread.wait_for_exit()
        tcp_rx_thread.wait_for_exit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Disconnection will issued after verification")
        wifi_dut.interfaces.wifi.leave()

        device_address = {'sa_addr': wifi_thread.dut_addr, 'da_addr': wifi_thread.ap_addr,
                          'ta_addr': wifi_thread.dut_addr, 'ra_addr': wifi_thread.ap_addr}

        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'ps_poll',
                        4: 'dhcp_4_way_handshake_packets', 5: 'tcp_syn_with_syn_ack_with_ack'}

        output = sl_collections.sniffer_validation_for_packet_filters(
            wifi_sniffer, sniffer_filter, device_address, filters_name=filters_name)

        logger().info(f'\n OUTPUT 1 = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("\n ================== Closing all LWIP sockets ================== \n")
        wifi_dut.interfaces.wifi.lwip_close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCPIPBypass,
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
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C919184')
def test_wifi_sdk_2_tcp_client_data_transfer_using_1_socket_c919184(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client, protocol):
    """This test case verifies 2 TCP client data transfer using 1 socket functionality using LWIP Stack"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                                     wifi_client=wifi_client,
                                     test_case_no=919184, leave=False, stop_capture=False)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        logger().info("Starting data transfer on socket 1")
        tcp_tx_thread1 = TCPTXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                     protocol=protocol, remote_socket_factory=remote_socket_factory, port=5001,
                                     no_of_pkts=100, close=True)
        tcp_tx_thread1.start()
        tcp_tx_thread1.wait_for_exit()

        logger().info("Creating socket 2 and starting data transfer on socket 1")
        tcp_tx_thread2 = TCPTXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                     protocol=protocol, remote_socket_factory=remote_socket_factory, port=5002)
        tcp_tx_thread2.start()
        tcp_tx_thread2.wait_for_exit()

        logger().info(
            "\n After successfully data Transfer from socket 2 and till then socket 1 is in idle state, check socket 1 is still in active state\n ")
        tcp_tx_thread1.tx_data_transfer()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Disconnection will issued after verification")
        wifi_dut.interfaces.wifi.leave()

        device_address = {'sa_addr': wifi_thread.dut_addr, 'da_addr': wifi_thread.ap_addr,
                          'ta_addr': wifi_thread.dut_addr, 'ra_addr': wifi_thread.ap_addr}

        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'ps_poll',
                        4: 'dhcp_4_way_handshake_packets', 5: 'tcp_syn_with_syn_ack_with_ack'}

        output = sl_collections.sniffer_validation_for_packet_filters(
            wifi_sniffer, sniffer_filter, device_address, filters_name=filters_name)

        logger().info(f'\n OUTPUT  = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("\n ================== Closing all LWIP sockets ================== \n")
        wifi_dut.interfaces.wifi.lwip_close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.test_src_map_id('C919194')
def test_wifi_sdk_dhcp_garp_verification_c919194(sniffer_filter, wifi_access_point, wifi_dut, sl_collections,
                                                 wifi_sniffer, request, wifi_client):
    """this test case verifies DHCP ACD no conflict GARP functionality using LWIP Stack"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                                     wifi_client=wifi_client,
                                     test_case_no=919194)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(filter_name='gratuitous_packet')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: GARP packet not found in sniffer packets'

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(dut_ip=wifi_thread.device_ip,
                                                                                        da_addr=wifi_thread.dut_addr,
                                                                                        filter_name='no_adc_conflict')
        assert not \
            wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2, negative_test=True)[
                'packet_count'], \
            'Sniffer: DHCP ACD conflict packet found in sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.test_src_map_id('C919223')
def test_wifi_sdk_dhcp_discon_connect_garp_verification_c919223(sniffer_filter, wifi_access_point, wifi_dut,
                                                                sl_collections, wifi_sniffer, request, wifi_client):
    """this test case verifies DHCP ACD no conflict GARP functionality upon disconnect and connect cycle, using LWIP Stack"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        i = 0
        logger().info(f"\n ======================== Starting the loop for 15 minutes ======================== \n")
        start_time = time.time()
        while time.time() - start_time < 900:
            logger().info(f"\n =============== Iteration number: {i + 1} ================= \n")
            i = i + 1
            wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         wifi_sniffer=wifi_sniffer,
                                         sl_collections=sl_collections, profile=profile,
                                         capture_filename=capture_filename, wifi_client=wifi_client,
                                         test_case_no=919223)

            wifi_thread.start()
            wifi_thread.wait_for_exit()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                filter_name='gratuitous_packet')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Sniffer: GARP packet not found in sniffer packets'

            packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                dut_ip=wifi_thread.device_ip,
                da_addr=wifi_thread.dut_addr,
                filter_name='no_adc_conflict')
            assert not \
                wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2, negative_test=True)[
                    'packet_count'], \
                'Sniffer: DHCP ACD conflict packet found in sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["disable_external_stack", "reset"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.test_src_map_id('C919225')
def test_wifi_sdk_dhcp_deinit_init_cycle_garp_verification_c919225(sniffer_filter, wifi_access_point, wifi_dut,
                                                                   sl_collections, wifi_sniffer, request, wifi_client):
    """this test case verifies DHCP ACD no conflict GARP functionality upon deinit and init cycle, using LWIP Stack"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        i = 0
        start_time = time.time()
        logger().info(
            f"\n ======================== Starting the loop for 15 minutes ====================== \n")
        while time.time() - start_time < 900:
            logger().info(f"\n ================= Iteration number: {i + 1} ================= \n")
            if i != 0:
                logger().info(f"\n =========== Initializing the network stack ===============\n")
                wifi_dut.interfaces.wifi.sl_net_init(mode='client')
            i = i + 1
            wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         wifi_sniffer=wifi_sniffer,
                                         sl_collections=sl_collections, profile=profile,
                                         capture_filename=capture_filename, wifi_client=wifi_client,
                                         test_case_no=919225)

            wifi_thread.start()
            wifi_thread.wait_for_exit()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                filter_name='gratuitous_packet')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Sniffer: GARP packet not found in sniffer packets'

            packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                dut_ip=wifi_thread.device_ip,
                da_addr=wifi_thread.dut_addr,
                filter_name='no_adc_conflict')
            assert not \
                wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2, negative_test=True)[
                    'packet_count'], \
                'Sniffer: DHCP ACD conflict packet found in sniffer packets'

            logger().info(f"\n =========== Deinitializing the network stack ===============\n")
            wifi_dut.interfaces.wifi.sl_net_deinit(mode='client')

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
        "dhcp_lease": "120",
    },
)
@pytest.mark.test_src_map_id('C919228')
def test_wifi_sdk_dhcp_renewal_LWIP_congestion_env_c919228(wifi_sniffer, wifi_access_point, wifi_dut,
                                                           request, sl_collections, sniffer_filter, wifi_client):
    """This test case verifies DHCP renewal functionality in LWIP stack under congestion environment using LWIP Stack"""
    capture_filename = request.node.name

    profile = {
        "ssid": "ssid_profile1",
        "channel": 6,
        "security": "OPEN",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                              test_case_no=919228, leave=False, stop_capture=False, wifi_client=wifi_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info(" wait for 300 seconds to capture DHCP renewal packets")
        time.sleep(300)
        logger().info("\n ============== Stop the sniffer =============== \n")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("\n =================== Disconnection will issued after verification ==================== \n")
        wifi_dut.interfaces.wifi.leave()

        device_address = {'sa_addr': wlan_obj.dut_addr, 'da_addr': wlan_obj.ap_addr, 'wlan_addr': wlan_obj.dut_addr}
        filters_name = {1: 'power_mgmt_bit', 2: 'dhcp', 3: 'dhcp_renewal'}
        output_1 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                        device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT = {output_1}\n')
        assert all(output_1.values()), 'Unable to find expected filter'

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.ap_addr,
            da_addr=wlan_obj.dut_addr,
            filter_name='dhcp_ack')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], \
            'Sniffer: DHCP ACK packet from AP not found in sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
        "dhcp_lease": "120",
    },
)
@pytest.mark.test_src_map_id('C919227')
def test_wifi_sdk_dhcp_renewal_LWIP_after_AP_reboot_c919227(wifi_sniffer, wifi_access_point, wifi_dut,
                                                            request, sl_collections, sniffer_filter, switch):
    """This test case verifies DHCP renewal functionality in LWIP stack after AP reboot using LWIP Stack"""
    capture_filename = request.node.name

    profile = {
        "ssid": "ssid_profile1",
        "channel": 6,
        "security": "OPEN",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                              test_case_no=919227, leave=False, stop_capture=False)

    try:
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("\n =================== Turning off the AP ===================\n")
        switch.interfaces.pdu_switch.turn_off(delay=20)
        logger().info("\n =================== Again turning on the AP ===================\n")
        switch.interfaces.pdu_switch.turn_on(delay=100)
        logger().info("\n =================== Successfully powered on AP ===================\n")
        logger().info(" wait for 300 seconds to capture DHCP renewal packets")
        time.sleep(300)

        logger().info("\n ============== Stop the sniffer =============== \n")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("\n =================== Disconnection will issued after verification ==================== \n")
        wifi_dut.interfaces.wifi.leave()

        device_address = {'sa_addr': wlan_obj.dut_addr, 'da_addr': wlan_obj.ap_addr, 'wlan_addr': wlan_obj.dut_addr}
        filters_name = {1: 'power_mgmt_bit', 2: 'dhcp', 3: 'dhcp_renewal'}
        output_1 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                        device_address, filters_name=filters_name)

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.ap_addr,
            da_addr=wlan_obj.dut_addr,
            filter_name='dhcp_ack')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], \
            'Sniffer: DHCP ACK packet from AP not found in sniffer packets'

        logger().info(f'\n OUTPUT = {output_1}\n')
        assert all(output_1.values()), 'Unable to find expected filter'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCPIPBypass,
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
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.test_src_map_id('C919195')
def test_wifi_sdk_udp_tx_lwip_c919195(sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer,
                                      request,
                                      net_perf_client, wifi_client, protocol):
    """This test case Verifies the udp client socket is open, send data,close functionality using LWIP Stack"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                                     wifi_client=wifi_client,
                                     test_case_no=919195, leave=False, stop_capture=False)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        udp_tx_thread = UDPTXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                    protocol=protocol, net_perf_client=net_perf_client)
        udp_tx_thread.start()
        udp_tx_thread.wait_for_exit()

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCPIPBypass,
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
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
@pytest.mark.test_src_map_id('C919190')
@pytest.mark.firmware_app("test_ipv6_lwip")
def test_wifi_sdk_ipv6_functionality_lwip_c919190(firmware_loader, sniffer_filter, wifi_access_point, wifi_dut,
                                                  sl_collections,
                                                  wifi_sniffer, request,
                                                  net_perf_client, wifi_client, protocol):
    """This test case Verifies the IPV6 functionality using LWIP Stack with default timer"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        logger().info(" ********** Raspberry pi Client connecting to Access Point ********* ")
        wifi_client.interfaces.wifi.join(ssid=profile["ssid"], security=SecurityMode.Open,
                                         passphrase=profile["passphrase"],
                                         channel=profile["channel"])

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                                     wifi_client=wifi_client, ip_version='ipv6', test_case_no=919311)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        logger().info("\n ====== Validate ICMPV6 message in Sniffer Capture ====== \n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(type=129,
                                                                                        filter_name='icmpv6_msg_type')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: ICMPV6 message not received'

        device_address = {'sa_addr': wifi_thread.dut_addr, 'da_addr': wifi_thread.ap_addr,
                          'ta_addr': wifi_thread.dut_addr, 'ra_addr': wifi_thread.ap_addr}

        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'ps_poll',
                        4: 'dhcp_4_way_handshake_packets'}

        output = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter, device_address,
                                                                      filters_name=filters_name)
        logger().info(f'\n OUTPUT RESULT = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
        "dhcp_lease": "120",
    },
)
@pytest.mark.test_src_map_id('C919176')
def test_wifi_sdk_dhcp_discover_failure_lwip_c919176(wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections,
                                                     sniffer_filter):
    """This test case verifies the DHCP discover functionality in LWIP stack with default timer"""
    capture_filename = request.node.name
    wlan_obj = WifiThread()

    try:
        logger().info(
            "\n =============== Configuring the Sniffer with access point channel and start the capture =============\n")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        da_addr = wifi_access_point.interfaces.wifi.bssid

        wifi_dut.interfaces.wifi.lwip_join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                           passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                           security=wifi_access_point.interfaces.wifi.security.name.lower(),
                                           timeout=60)

        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.213", dhcp_end="192.168.50.214")
        time.sleep(60)

        wifi_dut.interfaces.wifi.lwip_start_ip(expected_status=SLStatus.SL_STATUS_FAIL, timeout=120)
        logger().info(f"\n\n Observed the expected error code: 0x0001 (SL_STATUS_FAIL) \n\n")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")
        time.sleep(60)

        ip_config = wifi_dut.interfaces.wifi.lwip_start_ip(timeout=60)
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info(f"\n =========== DUT IP address is : {device_ip} =========== \n")

        logger().info("=========== pinging DUT ===============")
        status = sl_collections.ping(device_ip=device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        logger().info("\n ============= Disconnection will issued after verification =============== \n")
        wifi_dut.interfaces.wifi.leave()

        filters_name = {1: 'dhcp_discover_from_ta'}
        device_address = {'sa_addr': sa_addr, 'ta_addr': sa_addr, 'da_addr': da_addr}
        packet_filter = '        DHCP: Discover (1)'
        output_3 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter, device_address,
                                                                        filters_name=filters_name,
                                                                        packet_filter2=packet_filter)
        logger().info(f'\n OUTPUT 3 = {output_3}\n')
        assert all(output_3.values()), 'Unable to find expected filter'

        # Validate exponential progression in DHCP discover timing
        logger().info("======== Analyzing DHCP Discover Request Timing ========")
        time_deltas = wlan_obj.delta_between_dhcp_req_packet()

        if len(time_deltas) > 1:
            logger().info(f"DHCP discover time deltas: {time_deltas}")

            exponential_violations = []
            missed_packets = []
            tolerance = 0.5
            expected_power = 1  # Track the actual expected power level

            for i in range(1, len(time_deltas)):
                # Expected value based on current power level
                expected_value = 2 ** expected_power
                expected_min = expected_value * (1 - tolerance)  # Allow tolerance
                expected_max = expected_value * (1 + tolerance)

                # Check primary expected value
                matches_expected = (expected_min <= time_deltas[i] <= expected_max)

                if matches_expected:
                    # Perfect match, increment power for next iteration
                    expected_power += 1
                else:
                    # Check next power level to handle potential missed packets
                    next_expected_value = 2 ** (expected_power + 1)
                    next_expected_min = next_expected_value * (1 - tolerance)
                    next_expected_max = next_expected_value * (1 + tolerance)
                    matches_next_expected = (next_expected_min <= time_deltas[i] <= next_expected_max)

                    if matches_next_expected:
                        # Matches next level - packet was missed
                        missed_packets.append(expected_value)  # Log the missed packet for information
                        expected_power += 2  # Skip the missed power level and increment for next
                    else:
                        # Doesn't match expected or next expected - violation
                        violation = {
                            'index': i,
                            'expected_value': expected_value,
                            'next_expected_value': next_expected_value,
                            'current_delta': time_deltas[i],
                            'expected_range': f"{expected_min:.2f} - {expected_max:.2f}",
                            'next_range': f"{next_expected_min:.2f} - {next_expected_max:.2f}"
                        }
                        exponential_violations.append(violation)
                        expected_power += 1  # Continue with next power level
            logger().info(
                f"\n================ Missed Packets with expected Time-Interval: {missed_packets} ======================\n")
            logger().info(
                f"\n================ exponential violations Packets: {exponential_violations} ======================\n")
            assert len(
                exponential_violations) == 0, f"DHCP discover requests do not follow exponential backoff pattern: {exponential_violations}"
            assert len(
                missed_packets) <= 1, f"Need Manual Test case verification as Multiple missed DHCP discover packets detected: {missed_packets}"

        else:
            logger().info("Insufficient DHCP timing data for exponential analysis")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.parametrize("dhcp_lease", [60])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
        "dhcp_lease": "60",
    },
)
@pytest.mark.test_src_map_id('C919177')
def test_wifi_sdk_dhcp_request_failure_lwip_c919177(wifi_sniffer, wifi_access_point, wifi_dut, request,
                                                    sl_collections, sniffer_filter, dhcp_lease):
    """This test case verifies DHCP request functionality using LWIP Stack with default timer (legacy C683174 on LWIP)"""
    capture_filename = request.node.name
    mode = "power_save_low_latency"
    try:
        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        wifi_dut.interfaces.wifi.lwip_join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                           passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                           security=wifi_access_point.interfaces.wifi.security.name.lower(),
                                           timeout=60)

        ip_config = wifi_dut.interfaces.wifi.lwip_start_ip(timeout=60)
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"\n =========== DUT IP address is : {device_ip} =========== \n")

        logger().info(f"....Applying performance profile mode : {mode}")
        wifi_dut.interfaces.wifi.set_performance_profile(mode=mode)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='dhcp_request')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the dhcp request sniffer packets'

        device_address = {'sa_addr': sa_addr, 'da_addr': da_addr,
                          'ta_addr': sa_addr, 'ra_addr': da_addr}
        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response',
                        3: 'dhcp_4_way_handshake_packets'}

        output = sl_collections.sniffer_validation_for_packet_filters(
            wifi_sniffer, sniffer_filter, device_address, filters_name=filters_name)

        logger().info(f'\n OUTPUT 1 = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")
        time.sleep(60)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.test_src_map_id('C919224')
def test_wifi_sdk_dhcp_start_stop_c919224(wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections,
                                          sniffer_filter):
    """This test case verifies the DHCP start and stop functionality in LWIP stack using LWIP Stack with default timer"""
    capture_filename = request.node.name
    try:
        logger().info(
            "\n =============== Configuring the Sniffer with access point channel and start the capture =============\n")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        dut_addr = wifi_dut.interfaces.wifi.get_mac_address()
        ap_addr = wifi_access_point.interfaces.wifi.bssid

        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"

        wifi_dut.interfaces.wifi.lwip_join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                           passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                           security=wifi_access_point.interfaces.wifi.security.name.lower(),
                                           timeout=60)

        for i in range(20):
            logger().info(f"\n ============= DHCP Start-Stop Iteration: {i + 1} =============== \n")
            device_ip = wifi_dut.interfaces.wifi.dhcp_start(timeout=20)
            logger().info(f"\n ===========Ping the DUT IP: {device_ip} =========== \n")
            status = sl_collections.ping(device_ip=device_ip, ping_count=10)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST"
            wifi_dut.interfaces.wifi.dhcp_stop()

        logger().info("\n ============= Disconnection will issued after verification =============== \n")
        wifi_dut.interfaces.wifi.leave()
        logger().info("n ============= Stop Sniffer finally =============== \n")
        wifi_sniffer.interfaces.capture.stop_capture()

        device_address = {'sa_addr': dut_addr, 'da_addr': ap_addr,
                          'ta_addr': dut_addr, 'ra_addr': ap_addr}

        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response',
                        3: 'dhcp_4_way_handshake_packets'}

        output = sl_collections.sniffer_validation_for_packet_filters(
            wifi_sniffer, sniffer_filter, device_address, filters_name=filters_name)

        logger().info(f'\n OUTPUT 1 = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("remote_wiseconnect3", wifi=["sl_net_init_client", "reset"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client",
                                         "disable_external_stack"])
@pytest.mark.end_state("remote_wiseconnect3", wifi=["sl_net_deinit_client", "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C919193')
def test_wifi_sdk_verify_dora_after_dhcp_conflict_c919193(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                                          sniffer_filter, utf_constants, sl_collections, request,
                                                          remote_wiseconnect3):
    """ To verify DHCP DORA process after DHCP conflict scenario in LWIP stack with default timer"""
    capture_filename = request.node.name
    wlan_obj = WifiThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, capture_filename=capture_filename, ping_count=5,
                          test_case_no=919193, stop_capture=False, leave=True, power_save=False)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)

        wlan_obj.clear_device_arp_cache()
        time.sleep(2)

        logger().info(
            "\n =========== Connecting the 2nd device to Access point with same IP to create DHCP conflict =========== \n")
        remote_wiseconnect3.interfaces.wifi.lwip_join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                                      security=wifi_access_point.interfaces.wifi.security.name.lower(),
                                                      timeout=60)

        remote_wiseconnect3.interfaces.sapi.lwip_start_ip(static_ip=wlan_obj.device_ip,
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.50.1", timeout=10, vid=0)

        logger().info(f"\n ===========Ping the 2nd device with static IP: {wlan_obj.device_ip} =========== \n")
        status = sl_collections.ping(device_ip=wlan_obj.device_ip, ping_count=5)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST"

        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(
            "\n =========== Stopped previous capture and Starting Sniffer capture again to capture the DHCP packets after DHCP conflict scenario =========== \n")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename + "_after_conflict")

        logger().info(
            "\n =========== Connecting the 1st DUT to Access point to verify DORA process after DHCP conflict =========== \n")
        wifi_dut.interfaces.wifi.lwip_join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                           passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                           security=wifi_access_point.interfaces.wifi.security.name.lower(),
                                           timeout=60)
        wifi_dut.interfaces.wifi.lwip_start_ip(expected_status=SLStatus.SL_STATUS_FAIL, timeout=30)

        logger().info("\n =========== Stop the sniffer capture =========== \n")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("\n =========== DUT1 and DUT2 both will leave the network =========== \n")
        wifi_dut.interfaces.wifi.leave()
        remote_wiseconnect3.interfaces.wifi.leave()

        dut1_addr = wifi_dut.interfaces.wifi.get_mac_address()
        dut2_addr = remote_wiseconnect3.interfaces.wifi.get_mac_address()

        logger().info(
            "\n =========== Validating the DHCP decline packet from DUT1 in sniffer capture after DHCP conflict scenario =========== \n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut1_addr, filter_name="dhcp_decline")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1, packet_filter2="true")[
            'packet_count'], f"DHCP decline packets not found in sniffer packets"

        logger().info(
            "\n =========== Validating the DHCP discover packet from DUT1 in sniffer capture after DHCP conflict and decline scenario =========== \n")
        epoch_time = wlan_obj.extract_nak_epoch_time("./reports/filter2_file.txt")[0]
        packet_filter_2 = f'((wlan.sa == {dut1_addr}) and (wlan.da == ff:ff:ff:ff:ff:ff) and (dhcp.option.dhcp == 1) and (frame.time_epoch > {epoch_time}))'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter_2)[
            'packet_count'], f"DHCP discover packets not found in sniffer packets after DHCP conflict and DHCP decline"

        logger().info(
            "\n =========== Validating the DHCP reply packet from AP to DUT1 to indicate that Offer IP is already in use =========== \n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut2_addr, da_addr=dut1_addr, filter_name="arp_reply_pkt")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], f"DHCP decline packets not found in sniffer packets"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("remote_wiseconnect3", wifi=["sl_net_init_client", "reset"])
@pytest.mark.end_state("wifi_dut", wifi=["disable_external_stack", "reset"])
@pytest.mark.end_state("remote_wiseconnect3", wifi=["disable_external_stack", "reset"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.test_src_map_id('C919226')
def test_wifi_sdk_verify_dora_after_dhcp_conflict_loop_c919226(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                                               sniffer_filter, utf_constants, sl_collections, request,
                                                               remote_wiseconnect3):
    """ To verify DHCP DORA process after DHCP conflict scenario in loop in LWIP stack with default timer"""
    capture_filename = request.node.name
    wlan_obj = WifiThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, capture_filename=capture_filename, ping_count=5,
                          test_case_no=919226, stop_capture=False, leave=True, power_save=False)
    try:
        for i in range(5):
            logger().info(f"\n ======================== Iteration: {i + 1} ==================== \n")
            if i != 0:
                logger().info(f"\n =========== Initializing the network stack ===============\n")
                wifi_dut.interfaces.wifi.sl_net_init(mode='client')
            wlan_obj.capture_filename = f"{capture_filename}_iteration_{i + 1}"
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            time.sleep(2)

            wlan_obj.clear_device_arp_cache()
            time.sleep(2)

            logger().info(
                "\n =========== Connecting the 2nd device to Access point with same IP to create DHCP conflict =========== \n")
            remote_wiseconnect3.interfaces.wifi.lwip_join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                                          passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                                          security=wifi_access_point.interfaces.wifi.security.name.lower(),
                                                          timeout=60)

            remote_wiseconnect3.interfaces.sapi.lwip_start_ip(static_ip=wlan_obj.device_ip,
                                                              static_subnet="255.255.255.0",
                                                              static_gateway="192.168.50.1", timeout=10, vid=0)

            logger().info(f"\n ===========Ping the 2nd device with static IP: {wlan_obj.device_ip} =========== \n")
            status = sl_collections.ping(device_ip=wlan_obj.device_ip, ping_count=5)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST"

            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info(
                "\n =========== Stopped previous capture and Starting Sniffer capture again to capture the DHCP packets after DHCP conflict scenario =========== \n")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(
                capture_file=capture_filename + f"_after_conflict_iteration_{i + 1}")

            logger().info(
                "\n =========== Connecting the 1st DUT to Access point to verify DORA process after DHCP conflict =========== \n")
            wifi_dut.interfaces.wifi.lwip_join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                               passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                               security=wifi_access_point.interfaces.wifi.security.name.lower(),
                                               timeout=60)
            wifi_dut.interfaces.wifi.lwip_start_ip(expected_status=SLStatus.SL_STATUS_FAIL, timeout=30)

            logger().info("\n =========== Stop the sniffer capture =========== \n")
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("\n =========== DUT1 and DUT2 both will leave the network =========== \n")
            wifi_dut.interfaces.wifi.leave()
            remote_wiseconnect3.interfaces.wifi.leave()

            dut1_addr = wifi_dut.interfaces.wifi.get_mac_address()
            dut2_addr = remote_wiseconnect3.interfaces.wifi.get_mac_address()

            logger().info(
                "\n =========== Validating the DHCP decline packet from DUT1 in sniffer capture after DHCP conflict scenario =========== \n")
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=dut1_addr, filter_name="dhcp_decline")
            assert \
                wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                   packet_filter2="true")[
                    'packet_count'], f"DHCP decline packets not found in sniffer packets"

            logger().info(
                "\n =========== Validating the DHCP discover packet from DUT1 in sniffer capture after DHCP conflict and decline scenario =========== \n")
            epoch_time = wlan_obj.extract_nak_epoch_time("./reports/filter2_file.txt")[0]
            packet_filter_2 = f'((wlan.sa == {dut1_addr}) and (wlan.da == ff:ff:ff:ff:ff:ff) and (dhcp.option.dhcp == 1) and (frame.time_epoch > {epoch_time}))'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter_2)[
                'packet_count'], f"DHCP discover packets not found in sniffer packets after DHCP conflict and DHCP decline"

            logger().info(
                "\n =========== Validating the DHCP reply packet from AP to DUT1 to indicate that Offer IP is already in use =========== \n")
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=dut2_addr, da_addr=dut1_addr, filter_name="arp_reply_pkt")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], f"DHCP decline packets not found in sniffer packets"

            logger().info(f"\n =========== Deinitializing the network stack ===============\n")
            wifi_dut.interfaces.wifi.sl_net_deinit(mode='client')

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 4096}},
        # "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        # "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        # "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['sl_net_init_client'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "lwip_aws_disconnect", "disassociated",
                             "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.test_src_map_id('C919185')
def test_wifi_sdk_aws_tcp_shutdown_C919185(wifi_sniffer, wifi_access_point, wifi_dut, aws_iot_client, sl_collections,
                                           sniffer_filter, utf_constants, request, wifi_client):
    """
    Connect to AWS MQTT server subscribe to any topic, Receive data on the subscribed topic. Close the TCP connection
    and check the Connection stability.
    """
    client_id = 'client_c19546'
    topic = "topic_c19546"
    iterations = utf_constants.get('iter_count')
    capture_filename = request.node.name
    profile = {
        "ssid": "ssid_profile1",
        "channel": 6,
        "security": "OPEN",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    # wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
    #                              sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
    #                              wifi_client=wifi_client,
    #                              test_case_no=919180, leave=False, stop_capture=False)
    #
    # wifi_thread.start()
    # wifi_thread.wait_for_exit()
    wlan_obj = WifiThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, capture_filename=capture_filename, ping_count=5,
                          test_case_no=919193, stop_capture=False, leave=False, power_save=True)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)

        for iter_count in range(2):
            logger().info(
                f"\n ===================== Initiating aws test for iteration:{iter_count + 1} ================= \n")
            messages = []
            for i in range(3):
                messages.append(text_generator(size=10))
            logger().info(f"Messages are:{messages}")

            aws_obj = AwsConnection(wifi_dut=wifi_dut, aws_iot_client=aws_iot_client, client_id=client_id, topic=topic,
                                    messages=messages, qos=Si91xAwsQos.QOS0)
            logger().info("Initiating aws connect from DUT")
            assert aws_obj.connect_to_aws_server_from_dut(), "Failed to connect aws server from DUT"
            logger().info("Connecting to AWS server from DUT is successful")
            aws_obj.subscribe_from_dut()
            aws_obj.connect_to_aws_server_from_raspi()
            aws_obj.subscribe_from_raspi()
            time.sleep(5)

            for count, msg in enumerate(messages):
                logger().info(
                    f"Raspi is publishing message{count + 1} on topic:'{topic}'\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
                aws_obj.publish_from_raspi(msg)
                recv_msg = aws_obj.receive_aws_messages_from_dut()
                assert msg == recv_msg, "Failed to receive published message in DUT"
            logger().info("Successfully received all published messages\n")

            logger().info("Initiating AWS shutdown")
            wifi_dut.interfaces.wifi.lwipSockClose(socket_fd=0)
            logger().info("AWS shutdown success")
            wifi_dut.interfaces.wifi.lwip_aws_flags['connected'] = False

            logger().info(f"Iteration '{iter_count + 1}' completed")

        logger().info("Disconnection will issued after verification")
        wifi_dut.interfaces.wifi.leave()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        device_address = {'sa_addr': wlan_obj.dut_addr, 'da_addr': wlan_obj.ap_addr,
                          'ta_addr': wlan_obj.dut_addr, 'ra_addr': wlan_obj.ap_addr}

        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'power_mgmt_bit',
                        4: 'dhcp_4_way_handshake_packets', 5: 'tcp_syn_with_syn_ack_with_ack'}

        output = sl_collections.sniffer_validation_for_packet_filters(
            wifi_sniffer, sniffer_filter, device_address, filters_name=filters_name)

        logger().info(f'\n OUTPUT 1 = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 4096}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['sl_net_init_client'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "lwip_aws_disconnect", "disassociated",
                             "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.test_src_map_id('C919188')
def test_wifi_sdk_aws_receive_data_over_subscribed_topic_with_diff_len_C919188(wifi_sniffer, wifi_access_point,
                                                                               wifi_dut, aws_iot_client, sl_collections,
                                                                               sniffer_filter, utf_constants, request):
    """
    Connect to AWS MQTT server subscribe to any topic, Receive data on the subscribed topic. Close the TCP connection
    and check the Connection stability.
    """
    client_id = 'client_c919188'
    topic = "topic_c919188"
    capture_filename = request.node.name
    wlan_obj = WifiThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, capture_filename=capture_filename, ping_count=5,
                          test_case_no=919193, stop_capture=False, leave=False, power_save=True)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        messages = []
        # for size in (1, 10, 100, 512, 1000, 1390):
        for size in (1, 10, 100):
            messages.append(''.join(random.choice(string.ascii_uppercase) for _ in range(size)))
        logger().info(f"Messages are:{messages}")

        aws_obj = AwsConnection(wifi_dut=wifi_dut, aws_iot_client=aws_iot_client, client_id=client_id, topic=topic,
                                messages=messages, qos=Si91xAwsQos.QOS0)
        logger().info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(), "Failed to connect aws server from DUT"
        logger().info("Connecting to AWS server from DUT is successful")
        aws_obj.subscribe_from_dut()
        aws_obj.connect_to_aws_server_from_raspi()
        aws_obj.subscribe_from_raspi()
        time.sleep(5)

        for count, msg in enumerate(messages):
            logger().info(
                f"Raspi is publishing message{count + 1} on topic:'{topic}'\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
            aws_obj.publish_from_raspi(msg)
            recv_msg = aws_obj.receive_aws_messages_from_dut()
            assert msg == recv_msg, "Failed to receive published message in DUT"
            logger().info(f"\n Successfully received message{count + 1}: {msg} in DUT\n")
        logger().info("\nSuccessfully received all published messages\n")

        logger().info("Initiating AWS shutdown")
        wifi_dut.interfaces.wifi.lwipSockClose(socket_fd=0)
        logger().info("AWS shutdown success")
        wifi_dut.interfaces.wifi.lwip_aws_flags['connected'] = False

        logger().info("Disconnection will issued after verification")
        wifi_dut.interfaces.wifi.leave()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        device_address = {'sa_addr': wlan_obj.dut_addr, 'da_addr': wlan_obj.ap_addr,
                          'ta_addr': wlan_obj.dut_addr, 'ra_addr': wlan_obj.ap_addr}

        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'power_mgmt_bit',
                        4: 'dhcp_4_way_handshake_packets', 5: 'tcp_syn_with_syn_ack_with_ack'}

        output = sl_collections.sniffer_validation_for_packet_filters(
            wifi_sniffer, sniffer_filter, device_address, filters_name=filters_name)

        logger().info(f'\n OUTPUT 1 = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 4096}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['sl_net_init_client'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "lwip_aws_disconnect", "disassociated",
                             "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.test_src_map_id('C919187')
def test_wifi_sdk_aws_publish_data_with_different_length_C919187(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                 aws_iot_client, sl_collections, sniffer_filter,
                                                                 request):
    """
    Connect to AWS MQTT server subscribe to any topic, Receive data on the subscribed topic. Close the TCP connection
    and check the Connection stability.
    """
    client_id = 'client_c919187'
    topic = "topic_c919187"
    capture_filename = request.node.name
    wlan_obj = WifiThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, capture_filename=capture_filename, ping_count=5,
                          test_case_no=919193, stop_capture=False, leave=False, power_save=True)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        messages = []
        # for size in (1, 10, 100, 512, 1000, 1390):
        for size in (1, 10, 100):
            messages.append(''.join(random.choice(string.ascii_uppercase) for _ in range(size)))
        logger().info(f"Messages are:{messages}")

        aws_obj = AwsConnection(wifi_dut=wifi_dut, aws_iot_client=aws_iot_client, client_id=client_id, topic=topic,
                                messages=messages, qos=Si91xAwsQos.QOS0)
        logger().info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(), "Failed to connect aws server from DUT"
        logger().info("Connecting to AWS server from DUT is successful")
        aws_obj.subscribe_from_dut()
        aws_obj.connect_to_aws_server_from_raspi()
        aws_obj.subscribe_from_raspi()
        time.sleep(5)
        received_messages = []
        for count, msg in enumerate(messages):
            logger().info(
                f"DUT is publishing message{count + 1} on topic:'{topic}'\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
            aws_obj.publish_from_dut(message=msg, higher_data_len=1)
            time.sleep(10)
            received = aws_iot_client.interfaces.aws_iot.get_received_messages()[-1]
            received_messages.append(received.payload.decode('latin-1'))

        for i, message in enumerate(messages):
            assert any(message in recv_msg for recv_msg in
                       received_messages), f"Raspi did not received published message {message} from DUT"
            logger().info(f"Received Message{i + 1}: {message} ")

        logger().info("\nSuccessfully Published all messages from DUT and received at Rasp\n")

        logger().info("Initiating AWS shutdown")
        wifi_dut.interfaces.wifi.lwipSockClose(socket_fd=0)
        logger().info("AWS shutdown success")
        wifi_dut.interfaces.wifi.lwip_aws_flags['connected'] = False
        # aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()

        logger().info("Disconnection will issued after verification")
        wifi_dut.interfaces.wifi.leave()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        device_address = {'sa_addr': wlan_obj.dut_addr, 'da_addr': wlan_obj.ap_addr,
                          'ta_addr': wlan_obj.dut_addr, 'ra_addr': wlan_obj.ap_addr}

        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'power_mgmt_bit',
                        4: 'dhcp_4_way_handshake_packets', 5: 'tcp_syn_with_syn_ack_with_ack'}

        output = sl_collections.sniffer_validation_for_packet_filters(
            wifi_sniffer, sniffer_filter, device_address, filters_name=filters_name)

        logger().info(f'\n OUTPUT 1 = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 4096}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['sl_net_init_client'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "lwip_aws_unsubscribe", "lwip_aws_disconnect", "disassociated",
                             "disable_external_stack"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.parametrize("keep_alive", [60])
@pytest.mark.test_src_map_id('C919186')
def test_wifi_sdk_aws_mqtt_keep_alive_C919186(wifi_sniffer, wifi_access_point, wifi_dut, aws_iot_client, sl_collections,
                                              sniffer_filter, utf_constants, request, keep_alive):
    """
    Connect to AWS MQTT server subscribe to any topic, Receive data on the subscribed topic with different keepalive interval and check the Connection stability.
    """
    client_id = 'client_c19546'
    topic = "topic_c19546"
    capture_filename = request.node.name
    wlan_obj = WifiThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sl_collections=sl_collections, capture_filename=capture_filename, ping_count=5,
                          test_case_no=919193, stop_capture=False, leave=False, power_save=True)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        messages = []
        for i in range(3):
            messages.append(text_generator(size=10))
        logger().info(f"Messages are:{messages}")

        aws_obj = AwsConnection(wifi_dut=wifi_dut, aws_iot_client=aws_iot_client, client_id=client_id, topic=topic,
                                messages=messages, qos=Si91xAwsQos.QOS0, wifi_sniffer=wifi_sniffer)
        logger().info("Initiating aws connect from DUT")
        assert aws_obj.connect_to_aws_server_from_dut(keep_alive=keep_alive), "Failed to connect aws server from DUT"
        logger().info("Connecting to AWS server from DUT is successful")
        aws_obj.subscribe_from_dut()
        aws_obj.connect_to_aws_server_from_raspi()
        aws_obj.subscribe_from_raspi()
        time.sleep(5)
        for count, msg in enumerate(messages):
            logger().info(
                f"Raspi is publishing message{count + 1} on topic:'{topic}'\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
            aws_obj.publish_from_raspi(msg)
            recv_msg = aws_obj.receive_aws_messages_from_dut()
            assert msg == recv_msg, "Failed to receive published message in DUT"
        logger().info("Successfully received all published messages\n")

        time.sleep(keep_alive * 3)

        logger().info("Initiating AWS shutdown")
        wifi_dut.interfaces.wifi.lwipSockClose(socket_fd=0)
        logger().info("AWS shutdown success")
        wifi_dut.interfaces.wifi.lwip_aws_flags['connected'] = False
        aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()
        logger().info("Disconnection will issued after verification")
        wifi_dut.interfaces.wifi.leave()

        publish_ack, ping_request = aws_obj.mqtt_keep_alive_check(wlan_obj.dut_addr, request.node.name)
        logger().info(f"ping request timestamps : {ping_request}")
        if len(ping_request) >= 1 and len(publish_ack) >= 1:
            logger().info(
                f"len of publish ack is {len(publish_ack)} and number of ping request packets observed is : {len(ping_request)} publish ack : {publish_ack}, ping request : {ping_request}")
            assert ((keep_alive_time - 5)
                    < (float(ping_request[0]) - float(publish_ack[-1]))
                    <= (keep_alive_time + 5)
                    ), (f"mqtt ping request is not observed even after {keep_alive_time} is "
                        f"exhausted or before {keep_alive_time - 5} ")
            logger().info(
                f"MQTT KEEP ALIVE CHECK FUNCTIONALITY ** PING REQUEST PACKET OBSERVED AT DIFFERENCE OF {(float(ping_request[0]) - float(publish_ack[-1]))} SECONDS")

        if len(ping_request) > 1:
            for i in range(0, len(ping_request)):
                if i == len(ping_request) - 1:
                    break
                assert (
                        (keep_alive_time - 5)
                        < (float(ping_request[i + 1]) - float(ping_request[i]))
                        <= (keep_alive_time + 5)
                ), (
                    f"mqtt ping request is not observed even after {keep_alive_time} is "
                    f"exhausted or before {keep_alive_time - 5} and the ping re"
                    f"quest arrival time is {ping_request[i]} "
                )
                logger().info(
                    f"MQTT KEEP ALIVE CHECK FUNCTIONALITY ** PING REQUEST PACKET OBSERVED AT DIFFERENCE OF {(float(ping_request[i + 1]) - float(ping_request[i]))} SECONDS"
                )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)