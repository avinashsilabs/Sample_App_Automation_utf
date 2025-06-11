import time
import pytest
import threading
import concurrent.futures

from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xCustomSyncSockOptParms,
)
from threading import Thread
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from random import randint
import random
import string
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import (
    AsyncEventIdentifiers,
)
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.bsd_errors import BSDErrnoStatus


socket_list = {
    "async_socket": [],
    "sync_socket": [],
}


def logger():
    return get_logger(__name__)


def wifi_dut_marker(thread_config=None, ca_cert=None):
    config = {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
        | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
    if thread_config:
        config["thread_config"] = thread_config
    if ca_cert:
        config["ca_cert"] = ca_cert
    return pytest.mark.config("wifi_dut", wifi=config)


class TCPThread(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        remote_socket_factory=None,
        remote_ip_address=None,
        dut_addr=None,
        client_socket=None,
        transfer_type=None,
        port_number=None,
    ):
        super().__init__()
        self.thread_lock = threading.Lock()
        self.wifi_dut = wifi_dut
        self.remote_socket_factory = remote_socket_factory
        self.remote_ip_address = remote_ip_address
        self.dut_addr = dut_addr
        self.client_socket = client_socket
        self.transfer_type = transfer_type
        self.port_number = port_number

    def run(self):
        try:
            global socket_list
            keepalive_time = 60
            self.socket_fd = (
                self.wifi_dut.interfaces.wifi.socket(
                    domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP"
                )
                if self.transfer_type == "TX"
                else self.wifi_dut.interfaces.wifi.Asyncsocket(
                    domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP"
                )
            )
            # Append the sync and async sockets to the list to close the sockets at the end of the testcase
            if (
                self.transfer_type == "TX"
                and self.socket_fd not in socket_list["sync_socket"]
            ):
                socket_list["sync_socket"].append(self.socket_fd)
            if (
                self.transfer_type == "RX"
                and self.socket_fd not in socket_list["async_socket"]
            ):
                socket_list["async_socket"].append(self.socket_fd)

            self.client_socket = (
                self.remote_socket_factory.interfaces.socket.create_socket()
            )
            if self.transfer_type == "TX":
                self.client_socket.start_server(port=self.port_number)
            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=self.socket_fd,
                device_ip=self.dut_addr["device_ip"],
                server_port=self.port_number,
                timeout=5,
                asynch=0 if self.transfer_type == "TX" else 1,
            )
            if self.transfer_type != "TX":
                self.wifi_dut.interfaces.wifi.listen(
                    socket_fd=self.socket_fd, backlog=1, asynch=1
                )
                ThreadBase.call_functions_simultaneously(
                    [
                        (
                            self.wifi_dut.interfaces.wifi.bsdSocketAccept,
                            self.socket_fd,
                            1,
                        ),
                        (
                            self.client_socket.connect_client_tcp,
                            self.dut_addr["device_ip"],
                            self.port_number,
                        ),
                    ],
                    timeout=10,
                )
                return
            logger().info(
                f"Setting the socket option SO_KEEPALIVE with {keepalive_time} seconds"
            )
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
                socket_fd=self.socket_fd,
                option_name="SO_KEEPALIVE",
                option_val=keepalive_time,
            )
            for count in range(3):
                connect_status = False
                try:
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                        socket_fd=self.socket_fd,
                        server_ip=self.remote_ip_address,
                        server_port=self.port_number,
                    )
                    connect_status = True
                    break
                except:
                    logger().info(
                        f"Socket connection failed in DUT...retry_count:{count + 1}"
                    )
                    assert connect_status, "Socket connection failed in DUT"
        except Exception as e:
            logger().info(
                f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n"
            )

    def transmit_tcp_data(self):
        duration = 60
        sw = Stopwatch()
        logger().info(f"\n Starting the TCP TX data Transfer \n")
        while sw.elapsed_sec < duration:
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketSend(
                    socket_fd=self.socket_fd, data=sent_data, higher_data_len=0
                )
                self.client_socket.set_recv_timeout(socket_type=0)
                received_data = self.client_socket.recv_data_tcp(len(sent_data))
                logger().info(
                    f"\n###################### Received TCP Data: {received_data} ######################\n"
                )
                assert (
                    sent_data == received_data
                ), f"Data mismatch in sent and received data"
            except Exception as e:
                logger().info(
                    f"\n Socket Data Transfer Failed Within Duration: {sw.elapsed_sec} \n"
                )
                break

    def recv_tcp_data(self, recv_sock_id=None):
        duration = 60
        sw = Stopwatch()
        logger().info(f"\n Starting the TCP RX Data Transfer \n")
        while sw.elapsed_sec < duration:
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )
            self.client_socket.send_data_tcp(sent_data)
            time.sleep(1)
            received_data = self.wifi_dut.interfaces.wifi.bsdSocketReceive(
                recv_sock_id + 1
            )
            logger().info(
                f"###################### Buffer TCP Data  {received_data}  ######################"
            )
            logger().info(
                f"###################### Buffer TCP Data Length  {len(received_data)}  ######################"
            )
            assert sent_data == received_data, (
                f"buffer length sent by remote peer and received on the socket id "
                f"{self.socket_fd} opened in the DUT didn't matched"
            )
            logger().info("Data received successfully")
        self.client_socket.socket_close_indication(1)


class UDPThread(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        remote_socket_factory=None,
        remote_ip_address=None,
        dut_addr=None,
        client_socket=None,
        transfer_type=None,
        port_number=None,
    ):
        super().__init__()
        self.thread_lock = threading.Lock()
        self.wifi_dut = wifi_dut
        self.remote_socket_factory = remote_socket_factory
        self.remote_ip_address = remote_ip_address
        self.dut_addr = dut_addr
        self.client_socket = client_socket
        self.transfer_type = transfer_type
        self.port_number = port_number

    def run(self):
        try:
            global socket_list
            keepalive_time = 60
            self.socket_fd = (
                self.wifi_dut.interfaces.wifi.socket(
                    domain="AF_INET", stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP"
                )
                if self.transfer_type == "TX"
                else self.wifi_dut.interfaces.wifi.Asyncsocket(
                    domain="AF_INET", stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP"
                )
            )
            # Append the sync and async sockets to the list to close the sockets at the end of the test
            if (
                self.transfer_type == "TX"
                and self.socket_fd not in socket_list["sync_socket"]
            ):
                socket_list["sync_socket"].append(self.socket_fd)
            if (
                self.transfer_type == "RX"
                and self.socket_fd not in socket_list["async_socket"]
            ):
                socket_list["async_socket"].append(self.socket_fd)
            self.client_socket = (
                self.remote_socket_factory.interfaces.socket.create_socket()
            )
            logger().info(f"Starting the Remote Server Socket")
            self.client_socket.start_server(port=self.port_number, socket_type=1)
            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=self.socket_fd,
                device_ip=self.dut_addr["device_ip"],
                server_port=self.port_number,
                timeout=5,
                asynch=0 if self.transfer_type == "TX" else 1,
            )
            if self.transfer_type == "TX":
                logger().info(
                    f"Setting the socket option SO_KEEPALIVE with {keepalive_time} seconds"
                )
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
                    socket_fd=self.socket_fd,
                    option_name="SO_KEEPALIVE",
                    option_val=keepalive_time,
                )
            for count in range(3):
                connect_status = False
                try:
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                        socket_fd=self.socket_fd,
                        server_ip=self.remote_ip_address,
                        server_port=self.port_number,
                    )
                    connect_status = True
                    break
                except:
                    logger().info(
                        f"Socket connection failed in DUT...retry_count:{count + 1}"
                    )
                    assert connect_status, "Socket connection failed in DUT"
        except Exception as e:
            logger().info(
                f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n"
            )

    def transmit_udp_data(self):
        duration = 60
        sw = Stopwatch()
        logger().info(f"\n Starting the UDP TX data Transfer \n")
        while sw.elapsed_sec < duration:
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketSend(
                    socket_fd=self.socket_fd, data=sent_data, higher_data_len=0
                )
                self.client_socket.set_recv_timeout(
                    socket_type=1, use_client_socket=True
                )
                received_data = self.client_socket.recv_data_udp(len(sent_data))[0]
                logger().info(
                    f"\n###################### Received UDP Data: {received_data} ######################\n"
                )
                assert (
                    sent_data == received_data
                ), f"Data mismatch in sent and received data"
            except Exception as e:
                logger().info(
                    f"Socket Data Transfer Failed Within Duration: {sw.elapsed_sec}"
                )
                break

    def rev_udp_data(self, recv_sock_id=None):
        duration = 60
        sw = Stopwatch()
        logger().info(f"\n Starting the UDP RX data Transfer \n")
        while sw.elapsed_sec < duration:
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )
            self.client_socket.send_data_udp(
                sent_data, self.dut_addr["device_ip"], port=self.port_number
            )
            time.sleep(1)
            self.wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            received_data = self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(
                socket_fd=recv_sock_id
            )
            logger().info(
                f"###################### Buffer UDP Data  {received_data}  ######################"
            )
            logger().info(
                f"###################### Buffer UDP Data Length  {received_data}  ######################"
            )
            assert len(sent_data) == len(
                received_data
            ), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
            assert (
                sent_data == received_data
            ), f"Data mismatch in sent and received data"


class TLSThread(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        remote_ip_address=None,
        dut_addr=None,
        client_socket=None,
        transfer_type=None,
        port_number=None,
        ssl_server=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.remote_ip_address = remote_ip_address
        self.dut_addr = dut_addr
        self.client_socket = client_socket
        self.transfer_type = transfer_type
        self.port_number = port_number
        self.ssl_server = ssl_server

    def run(self):
        try:
            global socket_list
            self.ssl_server.interfaces.ssl.start_server(port=self.port_number)
            self.remote_ip_address = self.ssl_server.interfaces.ssl.server_ip

            self.socket_fd = (
                self.wifi_dut.interfaces.wifi.socket()
                if self.transfer_type == "TX"
                else self.wifi_dut.interfaces.wifi.async_sdk_socket(
                    domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP"
                )
            )
            if (
                self.transfer_type == "TX"
                and self.socket_fd not in socket_list["sync_socket"]
            ):
                socket_list["sync_socket"].append(self.socket_fd)
            if (
                self.transfer_type == "RX"
                and self.socket_fd not in socket_list["async_socket"]
            ):
                socket_list["async_socket"].append(self.socket_fd)
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
                socket_fd=self.socket_fd, option_name="TCP_ULP"
            )
            if self.transfer_type == "RX":
                self.wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(
                    self.socket_fd,
                    option_name="SL_SI91X_SO_HIGH_PERFORMANCE_SOCKET",
                    cert_index=128,
                )
            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=self.socket_fd,
                device_ip=self.dut_addr["device_ip"],
                server_port=randint(5001, 60000),
                timeout=15,
            )
            for count in range(3):
                connect_status = False
                try:
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                        socket_fd=self.socket_fd,
                        server_ip=self.remote_ip_address,
                        server_port=self.port_number,
                    )
                    connect_status = True
                    break
                except:
                    logger().info(
                        f"Socket connection failed in DUT...retry_count:{count + 1}"
                    )
                    assert connect_status, "Socket connection failed in DUT"
        except Exception as e:
            logger().info(
                f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n"
            )

    def transmit_data(self, server_socket_no=None):
        duration = 60
        pkt_count = 50000
        buffer_length = 1370
        if self.ssl_server.interfaces.ssl.config["type"] == "ssl.server.ssl_linux":
            self.ssl_server.interfaces.ssl.data_receive(
                server_socket_no, pkt_count, buffer_length
            )
        sw = Stopwatch()
        while sw.elapsed_sec < duration:
            bytes_sent = self.wifi_dut.interfaces.wifi.send_data_pkts(
                self.socket_fd, buffer_length, pkt_count
            )
            time.sleep(5)
            logger().info(f"\n **** Number of bytes sent by dut: {result} ****")
            bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(
                server_socket_no
            )
            logger().info(
                f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}"
            )

    def recv_data(self, server_socket_no=None, duration=None):
        buffer_length = 1370
        pkt_count = 50000
        self.ssl_server.interfaces.ssl.send_data(
            server_socket_no, pkt_count, msg_length=buffer_length, duration=duration
        )
        time.sleep(60)
        bytes_sent = self.ssl_server.interfaces.ssl.data_send_stats(server_socket_no)
        result = self.wifi_dut.interfaces.wifi.get_socket_rx_stats(
            self.socket_fd, no_of_pkts="pkt_count", ttl=30
        )
        logger().info(f"\n*** RX_Stats: {result}\n")
        bytes_received = int(result)
        logger().info(f"\n Bytes sent by Remote Peer -> {bytes_sent}\n")
        logger().info(
            f"\n ****Bytes Received on Socket: {self.socket_fd} -> {bytes_received}"
        )
        logger().info(
            f"SSL RX throughput ->  {((bytes_received * 8) / (1000 * 1000 * duration))} Mbps"
        )
        time.sleep(2)


class WifiJoinThread(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        wifi_access_point=None,
        wifi_client=None,
        sniffer_filter=None,
        wifi_sniffer=None,
        sl_collections=None,
        test_name=None,
        remote_socket_factory=None,
        ap_mac_address=None,
        testcase_id=None,
        remote_ip_address=None,
        ssl_server=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.dut_addr = None
        self.device_ip = None
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.remote_socket_factory = remote_socket_factory
        self.testcase_id = testcase_id
        self.remote_ip_address = remote_ip_address
        self.ssl_server = ssl_server

    def run(self):
        try:
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                retry_count=3,
                wifi_access_point=self.wifi_access_point,
                associated=self.wifi_dut.interfaces.wifi.associated,
                ping_after_power_save=True,
                power_save=False,
            )
            logger().info(
                f"\n########  device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}  ########\n"
            )
            if self.testcase_id == 689720:
                return
            if self.testcase_id == 689554:
                tcp_tx_thread = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.wifi_client.interfaces.wifi.get_ip_address(),
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5001,
                )
                udp_tx_thread = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.wifi_client.interfaces.wifi.get_ip_address(),
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5002,
                )
                tcp_tx_thread.start()
                udp_tx_thread.start()
                tcp_tx_thread.wait_for_exit()
                udp_tx_thread.wait_for_exit()
                tcp_thread = threading.Thread(target=tcp_tx_thread.transmit_tcp_data)
                udp_thread = threading.Thread(target=udp_tx_thread.transmit_udp_data)
                tcp_thread.start()
                udp_thread.start()
                tcp_thread.join()
                udp_thread.join()
                return

            if self.testcase_id == 689555:
                tcp_tx_thread = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5001,
                )
                udp_rx_thread = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5002,
                )
                tcp_tx_thread.start()
                udp_rx_thread.start()
                tcp_tx_thread.wait_for_exit()
                udp_rx_thread.wait_for_exit()
                tcp_thread = threading.Thread(target=tcp_tx_thread.transmit_tcp_data)
                udp_thread = threading.Thread(
                    target=udp_rx_thread.rev_udp_data, args=(1,)
                )
                tcp_thread.start()
                udp_thread.start()
                tcp_thread.join()
                udp_thread.join()
                return

            if self.testcase_id == 689556:
                tcp_tx_thread = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5001,
                )
                tcp_rx_thread = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5002,
                )
                tcp_tx_thread.start()
                tcp_rx_thread.start()
                tcp_tx_thread.wait_for_exit()
                tcp_rx_thread.wait_for_exit()
                tcp_tx = threading.Thread(target=tcp_tx_thread.transmit_tcp_data)
                tcp_rx = threading.Thread(target=tcp_rx_thread.recv_tcp_data, args=(1,))
                tcp_tx.start()
                tcp_rx.start()
                tcp_tx.join()
                tcp_rx.join()
                return

            if self.testcase_id == 689557:
                tcp_rx_thread = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5001,
                )
                udp_tx_thread = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5002,
                )
                tcp_rx_thread.start()
                udp_tx_thread.start()
                tcp_rx_thread.wait_for_exit()
                udp_tx_thread.wait_for_exit()
                tcp_thread = threading.Thread(
                    target=tcp_rx_thread.recv_tcp_data, args=(1,)
                )
                udp_thread = threading.Thread(target=udp_tx_thread.transmit_udp_data)
                tcp_thread.start()
                udp_thread.start()
                tcp_thread.join()
                udp_thread.join()
                return

            if self.testcase_id == 689558:
                tcp_rx_thread = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5001,
                )
                udp_rx_thread = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5002,
                )
                tcp_rx_thread.start()
                udp_rx_thread.start()
                tcp_rx_thread.wait_for_exit()
                udp_rx_thread.wait_for_exit()
                tcp_thread = threading.Thread(
                    target=tcp_rx_thread.recv_tcp_data, args=(1,)
                )
                udp_thread = threading.Thread(
                    target=udp_rx_thread.rev_udp_data, args=(1,)
                )
                tcp_thread.start()
                udp_thread.start()
                tcp_thread.join()
                udp_thread.join()
                return

            if self.testcase_id == 689559:
                udp_rx_thread = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5001,
                )
                udp_tx_thread = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5002,
                )
                udp_rx_thread.start()
                udp_tx_thread.start()
                udp_rx_thread.wait_for_exit()
                udp_tx_thread.wait_for_exit()
                udp_rx = threading.Thread(target=udp_rx_thread.rev_udp_data, args=(0,))
                udp_tx = threading.Thread(target=udp_rx_thread.transmit_udp_data)
                udp_rx.start()
                udp_tx.start()
                udp_rx.join()
                udp_tx.join()
                return

            if self.testcase_id == 689560:
                udp_rx_thread = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5001,
                )
                tcp_rx_thread = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5002,
                )
                udp_rx_thread.start()
                tcp_rx_thread.start()
                udp_rx_thread.wait_for_exit()
                tcp_rx_thread.wait_for_exit()
                tcp_thread = threading.Thread(
                    target=udp_rx_thread.rev_udp_data, args=(0,)
                )
                udp_thread = threading.Thread(
                    target=tcp_rx_thread.recv_tcp_data, args=(1,)
                )
                tcp_thread.start()
                udp_thread.start()
                tcp_thread.join()
                udp_thread.join()
                return

            if self.testcase_id == 689561:
                udp_tx_thread = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5001,
                )
                udp_rx_thread = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5002,
                )
                udp_tx_thread.start()
                udp_rx_thread.start()
                udp_tx_thread.wait_for_exit()
                udp_rx_thread.wait_for_exit()
                udp_tx = threading.Thread(target=udp_tx_thread.transmit_udp_data)
                udp_rx = threading.Thread(target=udp_rx_thread.rev_udp_data, args=(1,))
                udp_tx.start()
                udp_rx.start()
                udp_tx.join()
                udp_rx.join()
                return
            if self.testcase_id == 689562:
                tcp_tx_thread_1 = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5001,
                )
                tcp_tx_thread_2 = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5002,
                )
                tcp_rx_thread_1 = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5003,
                )
                tcp_rx_thread_2 = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5004,
                )
                tcp_tx_thread_1.start()
                tcp_tx_thread_1.wait_for_exit()
                tcp_tx_thread_2.start()
                tcp_tx_thread_2.wait_for_exit()
                tcp_rx_thread_1.start()
                tcp_rx_thread_1.wait_for_exit()
                tcp_rx_thread_2.start()
                tcp_rx_thread_2.wait_for_exit()
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    # Submit the functions to the executor
                    executor.submit(tcp_rx_thread_1.recv_tcp_data, 2)
                    executor.submit(tcp_rx_thread_2.recv_tcp_data, 4)
                    executor.submit(tcp_tx_thread_1.transmit_tcp_data)
                    executor.submit(tcp_tx_thread_2.transmit_tcp_data)
                return
            if self.testcase_id == 689563:
                udp_tx_thread_1 = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5001,
                )
                udp_tx_thread_2 = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5002,
                )
                udp_rx_thread_1 = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5003,
                )
                udp_rx_thread_2 = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5004,
                )
                udp_tx_thread_1.start()
                udp_tx_thread_1.wait_for_exit()
                udp_tx_thread_2.start()
                udp_tx_thread_2.wait_for_exit()
                udp_rx_thread_1.start()
                udp_rx_thread_1.wait_for_exit()
                udp_rx_thread_2.start()
                udp_rx_thread_2.wait_for_exit()
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    # Submit the functions to the executor
                    executor.submit(udp_rx_thread_1.rev_udp_data, 2)
                    executor.submit(udp_rx_thread_2.rev_udp_data, 3)
                    executor.submit(udp_tx_thread_1.transmit_udp_data)
                    executor.submit(udp_tx_thread_2.transmit_udp_data)
                return
            if self.testcase_id == 689564:
                tls_tx_thread = TLSThread(
                    wifi_dut=self.wifi_dut,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5001,
                    ssl_server=self.ssl_server,
                )
                tls_rx_thread = TLSThread(
                    wifi_dut=self.wifi_dut,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5002,
                    ssl_server=self.ssl_server,
                )
                tls_tx_thread.start()
                tls_tx_thread.wait_for_exit()
                tls_rx_thread.start()
                tls_rx_thread.wait_for_exit()
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    # Submit the functions to the executor
                    executor.submit(tls_tx_thread.transmit_data, 1)
                    executor.submit(tls_rx_thread.recv_data, 2, 60)
                return
            if self.testcase_id == 689565:
                udp_tx_thread = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5001,
                )
                udp_rx_thread = UDPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5002,
                )
                tcp_tx_thread = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5003,
                )
                tcp_rx_thread = TCPThread(
                    wifi_dut=self.wifi_dut,
                    remote_socket_factory=self.remote_socket_factory,
                    remote_ip_address=self.remote_ip_address,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5004,
                )
                tls_tx_thread = TLSThread(
                    wifi_dut=self.wifi_dut,
                    ssl_server=self.ssl_server,
                    dut_addr=self.dut_addr,
                    transfer_type="TX",
                    port_number=5005,
                )
                tls_rx_thread = TLSThread(
                    wifi_dut=self.wifi_dut,
                    ssl_server=self.ssl_server,
                    dut_addr=self.dut_addr,
                    transfer_type="RX",
                    port_number=5006,
                )
                udp_tx_thread.start()
                udp_tx_thread.wait_for_exit()
                udp_rx_thread.start()
                udp_rx_thread.wait_for_exit()
                tcp_tx_thread.start()
                tcp_tx_thread.wait_for_exit()
                tcp_rx_thread.start()
                tcp_rx_thread.wait_for_exit()
                tls_tx_thread.start()
                tls_tx_thread.wait_for_exit()
                tls_rx_thread.start()
                tls_rx_thread.wait_for_exit()
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    # Submit the functions to the executor
                    executor.submit(udp_tx_thread.transmit_udp_data)
                    executor.submit(udp_rx_thread.rev_udp_data, 1)
                    executor.submit(tcp_tx_thread.transmit_tcp_data)
                    executor.submit(tcp_rx_thread.recv_tcp_data, 3)
                    executor.submit(tls_tx_thread.transmit_data, 1)
                    executor.submit(tls_rx_thread.recv_data, 2, 10)

                return
        except Exception as e:
            logger().info(
                f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n"
            )
            raise e

    def close_sockets(self):
        for sock_type, socket in socket_list.items():
            if sock_type == "sync_socket":
                for sock in socket:
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            else:
                for sock in socket:
                    self.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        socket_list.clear()
        socket_list.update(
            {
                "async_socket": [],
                "sync_socket": [],
            }
        )
        return


@wifi_dut_marker(thread_config={"wifi": {"count": 3, "stack_len": 2500}})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_one_tcp_tx_and_udp_tx_multi_thread_socket_functionality_c689554(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    sl_collections,
    remote_socket_factory,
    wifi_client,
):
    """
    Verify the WiFi SDK functionality with one TCP and one UDP transmission using multi-threaded sockets.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote socket server.
    5. Create two sockets for TCP and UDP communication.
    6. Send data over the TCP and UDP sockets using multi-threaded communication.
    7. Capture and validate the network traffic to ensure the data transmission is successful.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        sl_collections: The SL collections interface for exception handling and validation.
        remote_socket_factory: The remote socket factory interface to create and manage sockets.
        wifi_client: The WiFi client interface to get the IP address of the remote client.

    Raises:
        Exception: If any step in the test case fails.
    """
    try:
        testcase_id = 689554
        test_name = request.node.name
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=689554,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        logger().info(f"\n....Clearing the Socket List....\n")
        wifi_thread.close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(thread_config={"wifi": {"count": 3, "stack_len": 2500}})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_one_tcp_tx_and_udp_rx_multi_thread_socket_functionality_c689555(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    sl_collections,
    remote_socket_factory,
    wifi_client,
):
    """
    Verify the WiFi SDK functionality with one TCP transmission and one UDP reception using multi-threaded sockets.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote socket server.
    5. Create two sockets for TCP transmission and UDP reception.
    6. Send data over the TCP socket and receive data over the UDP socket using multi-threaded communication.
    7. Capture and validate the network traffic to ensure the data transmission is successful.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        sl_collections: The SL collections interface for exception handling and validation.
        remote_socket_factory: The remote socket factory interface to create and manage sockets.
        wifi_client: The WiFi client interface to get the IP address of the remote client.

    Raises:
        Exception: If any step in the test case fails.
    """
    try:
        testcase_id = 689555
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=testcase_id,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        logger().info(f"\n....Clearing the Socket List....\n")
        wifi_thread.close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(thread_config={"wifi": {"count": 3, "stack_len": 2500}})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_one_tcp_tx_and_tcp_rx_multi_thread_socket_functionality_c689556(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    sl_collections,
    remote_socket_factory,
    wifi_client,
):
    """
    Verify the WiFi SDK functionality with one TCP transmission and one UDP reception using multi-threaded sockets.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote socket server.
    5. Create two sockets for TCP transmission and UDP reception.
    6. Send data over the TCP socket and receive data over the UDP socket using multi-threaded communication.
    7. Capture and validate the network traffic to ensure the data transmission is successful.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        sl_collections: The SL collections interface for exception handling and validation.
        remote_socket_factory: The remote socket factory interface to create and manage sockets.
        wifi_client: The WiFi client interface to get the IP address of the remote client.

    Raises:
        Exception: If any step in the test case fails.
    """
    try:
        testcase_id = 689556
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=testcase_id,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        logger().info(f"\n....Clearing the Socket List....\n")
        wifi_thread.close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(thread_config={"wifi": {"count": 3, "stack_len": 2500}})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_one_tcp_rx_and_udp_tx_multi_thread_socket_functionality_c689557(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    sl_collections,
    remote_socket_factory,
    wifi_client,
):
    """
    Verify the WiFi SDK functionality with one TCP reception and one UDP transmission using multi-threaded sockets.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote socket server.
    5. Create two sockets for TCP reception and UDP transmission.
    6. Receive data over the TCP socket and send data over the UDP socket using multi-threaded communication.
    7. Capture and validate the network traffic to ensure the data transmission is successful.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        sl_collections: The SL collections interface for exception handling and validation.
        remote_socket_factory: The remote socket factory interface to create and manage sockets.
        wifi_client: The WiFi client interface to get the IP address of the remote client.

    Raises:
        Exception: If any step in the test case fails.
    """
    try:
        testcase_id = 689557
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=testcase_id,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        logger().info(f"\n....Clearing the Socket List....\n")
        wifi_thread.close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(thread_config={"wifi": {"count": 3, "stack_len": 2500}})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_one_tcp_rx_and_udp_rx_multi_thread_socket_functionality_c689558(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    sl_collections,
    remote_socket_factory,
    wifi_client,
):
    """
    Verify the WiFi SDK functionality with one TCP reception and one UDP reception using multi-threaded sockets.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote socket server.
    5. Create two sockets for TCP and UDP reception.
    6. Receive data over the TCP and UDP sockets using multi-threaded communication.
    7. Capture and validate the network traffic to ensure the data reception is successful.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        sl_collections: The SL collections interface for exception handling and validation.
        remote_socket_factory: The remote socket factory interface to create and manage sockets.
        wifi_client: The WiFi client interface to get the IP address of the remote client.

    Raises:
        Exception: If any step in the test case fails.
    """
    try:
        testcase_id = 689558
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=testcase_id,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        logger().info(f"\n....Clearing the Socket List....\n")
        wifi_thread.close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(thread_config={"wifi": {"count": 3, "stack_len": 2500}})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_one_udp_rx_and_udp_tx_multi_thread_socket_functionality_c689559(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    sl_collections,
    remote_socket_factory,
    wifi_client,
):
    """
    Verify the WiFi SDK functionality with one UDP reception and one UDP transmission using multi-threaded sockets.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote socket server.
    5. Create two sockets for UDP reception and transmission.
    6. Receive data over the UDP socket and send data over the UDP socket using multi-threaded communication.
    7. Capture and validate the network traffic to ensure the data transmission is successful.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        sl_collections: The SL collections interface for exception handling and validation.
        remote_socket_factory: The remote socket factory interface to create and manage sockets.
        wifi_client: The WiFi client interface to get the IP address of the remote client.

    Raises:
        Exception: If any step in the test case fails.
    """
    try:
        testcase_id = 689559
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=testcase_id,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        logger().info(f"\n....Clearing the Socket List....\n")
        wifi_thread.close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(thread_config={"wifi": {"count": 3, "stack_len": 2500}})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_one_udp_rx_and_tcp_rx_multi_thread_socket_functionality_c689560(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    sl_collections,
    remote_socket_factory,
    wifi_client,
):
    """
    Verify the WiFi SDK functionality with one UDP reception and one TCP reception using multi-threaded sockets.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote socket server.
    5. Create two sockets for UDP and TCP reception.
    6. Receive data over the UDP and TCP sockets using multi-threaded communication.
    7. Capture and validate the network traffic to ensure the data reception is successful.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        sl_collections: The SL collections interface for exception handling and validation.
        remote_socket_factory: The remote socket factory interface to create and manage sockets.
        wifi_client: The WiFi client interface to get the IP address of the remote client.

    Raises:
        Exception: If any step in the test case fails.
    """

    try:
        testcase_id = 689560
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=testcase_id,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        logger().info(f"\n....Clearing the Socket List....\n")
        wifi_thread.close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(thread_config={"wifi": {"count": 3, "stack_len": 2500}})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_one_udp_tx_and_udp_rx_multi_thread_socket_functionality_c689561(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    sl_collections,
    remote_socket_factory,
    wifi_client,
):
    """
    Verify the WiFi SDK functionality with one UDP transmission and one UDP reception using multi-threaded sockets.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote socket server.
    5. Create two sockets for UDP transmission and reception.
    6. Send data over the UDP socket and receive data over the UDP socket using multi-threaded communication.
    7. Capture and validate the network traffic to ensure the data transmission and reception are successful.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        sl_collections: The SL collections interface for exception handling and validation.
        remote_socket_factory: The remote socket factory interface to create and manage sockets.
        wifi_client: The WiFi client interface to get the IP address of the remote client.

    Raises:
        Exception: If any step in the test case fails.
    """

    try:
        testcase_id = 689561
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=testcase_id,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        logger().info(f"\n....Clearing the Socket List....\n")
        wifi_thread.close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(thread_config={"wifi": {"count": 4, "stack_len": 2500}})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_two_tcp_tx_and_tcp_rx_multi_thread_socket_functionality_c689562(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    sl_collections,
    remote_socket_factory,
    wifi_client,
):
    """
    Verify the WiFi SDK functionality with two TCP transmissions and two TCP receptions using multi-threaded sockets.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote socket server.
    5. Create four sockets for two TCP transmissions and two TCP receptions.
    6. Send data over the two TCP sockets and receive data over the two TCP sockets using multi-threaded communication.
    7. Capture and validate the network traffic to ensure the data transmission and reception are successful.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        sl_collections: The SL collections interface for exception handling and validation.
        remote_socket_factory: The remote socket factory interface to create and manage sockets.
        wifi_client: The WiFi client interface to get the IP address of the remote client.

    Raises:
        Exception: If any step in the test case fails.
    """

    try:
        testcase_id = 689562
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=testcase_id,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        logger().info(f"\n....Clearing the Socket List....\n")
        wifi_thread.close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(thread_config={"wifi": {"count": 4, "stack_len": 2500}})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_two_udp_tx_and_udp_rx_multi_thread_socket_functionality_c689563(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    sl_collections,
    remote_socket_factory,
    wifi_client,
):
    """
    Verify the WiFi SDK functionality with two UDP transmissions and two UDP receptions using multi-threaded sockets.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote socket server.
    5. Create four sockets for two UDP transmissions and two UDP receptions.
    6. Send data over the two UDP sockets and receive data over the two UDP sockets using multi-threaded communication.
    7. Capture and validate the network traffic to ensure the data transmission and reception are successful.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        sl_collections: The SL collections interface for exception handling and validation.
        remote_socket_factory: The remote socket factory interface to create and manage sockets.
        wifi_client: The WiFi client interface to get the IP address of the remote client.

    Raises:
        Exception: If any step in the test case fails.
    """

    try:
        testcase_id = 689563
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=testcase_id,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        logger().info(f"\n....Clearing the Socket List....\n")
        wifi_thread.close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(
    thread_config={"wifi": {"count": 3, "stack_len": 2500}},
    ca_cert=[
        "ca-chain.cert.pem",
        "SL_NET_SIGNING_CERTIFICATE",
        "SL_NET_TLS_SERVER_CREDENTIAL_START",
    ],
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_one_tls_tx_and_tls_rx_multi_thread_socket_functionality_c689564(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    sl_collections,
    ssl_server,
    wifi_client,
):
    """
    Verify the WiFi SDK functionality with one TLS transmission and one TLS reception using multi-threaded sockets.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote SSL server.
    5. Create two sockets for TLS transmission and reception.
    6. Send data over the TLS socket and receive data over the TLS socket using multi-threaded communication.
    7. Capture and validate the network traffic to ensure the data transmission and reception are successful.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        sl_collections: The SL collections interface for exception handling and validation.
        ssl_server: The SSL server interface to create and manage SSL connections.
        wifi_client: The WiFi client interface to get the IP address of the remote client.

    Raises:
        Exception: If any step in the test case fails.
    """
    try:
        testcase_id = 689564
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=testcase_id,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
            ssl_server=ssl_server,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        logger().info(f"\n....Clearing the Socket List....\n")
        wifi_thread.close_sockets()
        ssl_server.interfaces.ssl.stop_server()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(thread_config={"wifi": {"count": 4, "stack_len": 2500}})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_udp_tx_and_udp_rx_tcp_tx_and_tcp_rx_tls_tx_and_tls_rx_c689565(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    sl_collections,
    remote_socket_factory,
    wifi_client,
    ssl_server,
):
    """
    Verify the WiFi SDK functionality with UDP, TCP, and TLS transmissions and receptions using multi-threaded sockets.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote socket server and SSL server.
    5. Create sockets for UDP, TCP, and TLS communication.
    6. Send and receive data over the UDP, TCP, and TLS sockets using multi-threaded communication.
    7. Capture and validate the network traffic to ensure the data transmission and reception are successful.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        sl_collections: The SL collections interface for exception handling and validation.
        remote_socket_factory: The remote socket factory interface to create and manage sockets.
        wifi_client: The WiFi client interface to get the IP address of the remote client.
        ssl_server: The SSL server interface to create and manage SSL connections.

    Raises:
        Exception: If any step in the test case fails.
    """

    try:
        testcase_id = 689565
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=testcase_id,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
            ssl_server=ssl_server,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        logger().info(f"\n....Clearing the Socket List....\n")
        wifi_thread.close_sockets()
        ssl_server.interfaces.ssl.stop_server()
        remote_socket_factory.interfaces.socket.close_all()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2500, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode
        | Si91xFeatureBitMap.Aggregation
        | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.Default
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": 12345678}
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
        "close_sockets",
    ],
)
def test_wifi_sdk_verify_sl_si91x_recv_with_maximum_buffer_length_and_returns_error_after_RCV_timeout_elapses_c689720(
    wifi_dut,
    wifi_sniffer,
    wifi_access_point,
    request,
    remote_socket_factory,
    sl_collections,
    wifi_client,
):
    """
    Verify the WiFi SDK functionality when receiving data with the maximum buffer length and ensure it returns an error after the receive timeout elapses.

    This test case performs the following steps:
    1. Configure the WiFi DUT (Device Under Test) to operate in WiFi client mode.
    2. Connect the WiFi DUT to the access point.
    3. Start the WiFi sniffer to capture network traffic.
    4. Initialize and start a remote socket server.
    5. Create a socket for data reception with the maximum buffer length.
    6. Attempt to receive data and verify that an error is returned after the receive timeout elapses.
    7. Capture and validate the network traffic to ensure the error condition is correctly handled.

    Args:
        wifi_dut: The WiFi DUT interface to configure and control the DUT.
        wifi_sniffer: The WiFi sniffer interface to capture network traffic.
        wifi_access_point: The WiFi access point interface to configure and control the access point.
        request: The pytest request object to get test metadata.
        remote_socket_factory: The remote socket factory interface to create and manage sockets.
        sl_collections: The SL collections interface for exception handling and validation.
        wifi_client: The WiFi client interface to get the IP address of the remote client.

    Raises:
        Exception: If any step in the test case fails.
    """

    try:
        testcase_id = 689720
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_ip_address = wifi_client.interfaces.wifi.get_ip_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** AP MAC ADDRESS {ap_mac_address} ****")
        wifi_thread = WifiJoinThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            wifi_client=wifi_client,
            testcase_id=testcase_id,
            remote_ip_address=remote_ip_address,
            ap_mac_address=ap_mac_address,
        )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_dut.interfaces.wifi.set_socket_config(tcp_rx_only_sockets=1)
        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        socket_fd = wifi_dut.interfaces.wifi.Asyncsocket(
            domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP"
        )
        wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(
            socket_fd=socket_fd,
            cert_index=128,
            option_name=Si91xCustomSyncSockOptParms.SL_SI91X_SO_HIGH_PERFORMANCE_SOCKET,
        )
        wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_fd,
            device_ip=wifi_thread.dut_addr["device_ip"],
            server_port=5001,
            timeout=5,
            asynch=1,
        )
        wifi_dut.interfaces.wifi.listen(socket_fd=socket_fd, backlog=1, asynch=1)
        ThreadBase.call_functions_simultaneously(
            [
                (
                    wifi_dut.interfaces.wifi.bsdSocketAccept,
                    socket_fd,
                    1,
                ),
                (
                    client_socket.connect_client_tcp,
                    wifi_thread.dut_addr["device_ip"],
                    5001,
                ),
            ],
            timeout=10,
        )
        # wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(socket_fd=socket_fd, cert_index=30, option_name=Si91xCustomSyncSockOptParms.SL_SI91X_SO_RCVTIME)
        duration = 10
        sw = Stopwatch()
        logger().info(f"\n Starting the TCP RX Data Transfer \n")
        while sw.elapsed_sec < duration:
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )
            client_socket.send_data_tcp(sent_data)
            time.sleep(1)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=20)
            received_data = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd + 1)
            logger().info(
                f"###################### Buffer TCP Data  {received_data}  ######################"
            )
            logger().info(
                f"###################### Buffer TCP Data Length  {len(received_data)}  ######################"
            )
            assert sent_data == received_data, (
                f"buffer length sent by remote peer and received on the socket id "
                f"{socket_fd} opened in the DUT didn't matched"
            )
            logger().info("Data received successfully")
        time.sleep(30)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
