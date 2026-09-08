import socket
import time
import pytest
import re
from utf_wiseconnect_3.wifi.siwx3xx.tests.devices.siwx3xx import (
    Siwx3xxCoexMode,
    Siwx3xxTCPIPFeatureBitMap,
    Siwx3xxExtTCPIPFeatureBitMap,
    Siwx3xxFeatureBitMap,
    Siwx3xxConfigFeatureBitMap,
    Siwx3xxExtCustomFeatureBitMap,
    Siwx3xxPowerSaveModes,
    DeviceConstants,
    Siwx3xxPowerSaveProcedureTypes,
    Siwx3xxCustomFeatureBitMap,
    SocketOptions,
    Siwx3xxOperatingMode,
    Siwx3xxCustomSyncSockOptParms,
    Siwx3xxJoinFeatureBitMap
)
from threading import Thread
import threading
from functools import partial
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from random import randint
import random
import string
from utf_wiseconnect_3.wifi.siwx3xx.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf_wiseconnect_3.wifi.siwx3xx.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.bsd_errors import BSDErrnoStatus

from utf.interfaces.wifi import SecurityMode, Standard
from utf.utf_config import UtfConfig

"""The testcases added in this file run below test steps for DUT(Soc917)
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP or UDP socket(Client/server) at DUT/RASPBERRY - PI
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
        8. Verify TCP rx & tx with high performance sockets
        9. Verify data transfer with different window size and with different RSSI values.

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. NUC device for Sniffer

    Author: Venkatesulu Ekambaram
"""


def logger():
    return get_logger(__name__)


# SLWifiCLI already wraps DUT lwip.* commands with these camelCase methods:
# lwipSocketCreate / Bind / Connect / Send / Listen / Accept / SockClose, plus wifi.iperf().


def lwip_socket_create(wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP"):
    """Create a lwIP BSD socket via SLWifiCLI.lwipSocketCreate (issues lwip.socket_create)."""
    wifi = wifi_dut.interfaces.wifi
    logger().info(f"lwip.socket_create domain={domain} type={sock_type} protocol={protocol}")
    socket_id = wifi.lwipSocketCreate(domain=domain, stream_type=sock_type, protocol=protocol)
    logger().info(f"Socket open successfully : {socket_id}")
    return socket_id


def lwip_bind(wifi_dut, socket_fd, ip_address, port, ip_version=4, reserved=4):
    """Bind a lwIP socket via SLWifiCLI.lwipSocketBind (issues lwip.bind)."""
    wifi = wifi_dut.interfaces.wifi
    logger().info(f"lwip.bind fd={socket_fd} ip={ip_address} port={port} ip_version={ip_version}")
    return wifi.lwipSocketBind(
        socket_fd=socket_fd, device_ip=str(ip_address), ip_len=reserved,
        server_port=port)


def lwip_close(wifi_dut, socket_fd):
    """Close a lwIP socket via SLWifiCLI.lwipSockClose (issues lwip.close)."""
    wifi = wifi_dut.interfaces.wifi
    logger().info(f"lwip.close fd={socket_fd}")
    return wifi.lwipSockClose(socket_fd=socket_fd)


def lwip_connect(wifi_dut, socket_fd, ip_address, port, ip_length=4):
    """Connect a lwIP socket via SLWifiCLI.lwipSocketConnect (issues lwip.connect)."""
    wifi = wifi_dut.interfaces.wifi
    logger().info(f"lwip.connect fd={socket_fd} ip={ip_address} port={port}")
    return wifi.lwipSocketConnect(
        socket_fd=socket_fd, server_ip=str(ip_address), server_port=port, ip_len=ip_length)


def lwip_listen(wifi_dut, socket_fd, backlog=1):
    """Listen via SLWifiCLI.lwipSocketListen (issues lwip.listen)."""
    return wifi_dut.interfaces.wifi.lwipSocketListen(socket_fd=socket_fd, backlog=backlog)


def lwip_accept(wifi_dut, socket_fd):
    """Accept via SLWifiCLI.lwipSocketAccept (issues lwip.accept)."""
    return wifi_dut.interfaces.wifi.lwipSocketAccept(socket_fd=socket_fd)


def lwip_send(wifi_dut, socket_fd, data, higher_data_len=1):
    """Send via SLWifiCLI.lwipSocketSend (issues lwip.send)."""
    return wifi_dut.interfaces.wifi.lwipSocketSend(
        socket_fd=socket_fd, data=data, higher_data_len=higher_data_len)


def lwip_send_to(wifi_dut, socket_fd, data, ip_address, port, ip_length=4, higher_data_len=1):
    """UDP send via lwip.send_to (no dedicated SLWifiCLI wrapper)."""
    wifi = wifi_dut.interfaces.wifi
    line = (
        f"lwip.send_to {socket_fd} {higher_data_len} -d {data} "
        f"{ip_address} {ip_length} {port}"
    )
    logger().info(f"lwip.send_to fd={socket_fd} ip={ip_address} port={port}")
    status, receive_data = wifi.issue_command(line=line, timeout=10)
    wifi.verify_status(status)
    return receive_data


def lwip_send_data_pkts(wifi_dut, socket_id, pkt_length, no_of_pkts, time_interval=1,
                        server_ip=None, server_port=None, expected_status=None, proto_type=0):
    """Send no_of_pkts over a lwIP socket (TCP send / UDP send_to)."""
    del time_interval, expected_status
    payload = "A" * pkt_length
    total = 0
    for _ in range(no_of_pkts):
        if proto_type == 0:
            lwip_send(wifi_dut, socket_fd=socket_id, data=payload, higher_data_len=1)
        else:
            lwip_send_to(
                wifi_dut, socket_fd=socket_id, data=payload,
                ip_address=server_ip, port=server_port)
        total += pkt_length
    return total


def lwip_set_opt(wifi_dut, socket_fd, option_level="SOL_SOCKET", option_name="SO_KEEPALIVE",
                 option_value=None):
    """Set a lwIP socket option via SLWifiCLI.lwipSetSocketOpt (issues lwip.set_opt)."""
    return wifi_dut.interfaces.wifi.lwipSetSocketOpt(
        socket_fd=socket_fd, option_val=str(option_value),
        option_level=option_level, option_name=option_name)


def lwip_iperf(wifi_dut, local_ip, remote_ip, local_port, remote_port, throughput_type=1,
               protocol_family=2, socket_type=1, socket_protocol=6,
               data_len=1460, ttl_sec=60, qos=0, async_mode=0, ip_type=4):
    """Run lwIP iperf via SLWifiCLI.iperf(), which issues lwip.iperf."""
    wifi = wifi_dut.interfaces.wifi
    logger().info(
        f"lwip.iperf type={throughput_type} local={local_ip}:{local_port} "
        f"remote={remote_ip}:{remote_port} data_len={data_len}")
    return wifi.iperf(
        family=protocol_family, transfer_type=socket_type, protocol=socket_protocol,
        local_port=local_port, local_ip=str(local_ip), remote_ip=str(remote_ip),
        remote_port=remote_port, size=data_len, ttl=ttl_sec,
        throughput_type=throughput_type, qos=qos, async_socket=async_mode,
        timeout=ttl_sec + 40)


def lwip_tcp_connect_with_retry(wifi_dut, socket_fd, server_ip, server_port, retries=3, retry_delay_s=10,
                                bind_ip=None):
    """Retry lwip.connect. A failed connect leaves the fd unusable (errno 107), so
    recreate and re-bind when bind_ip is provided."""
    sock = socket_fd
    last_error = None
    for count in range(retries):
        try:
            lwip_connect(wifi_dut, socket_fd=sock, ip_address=server_ip, port=server_port)
            logger().info("*********** Socket connection is successful ************")
            return sock
        except Exception as exc:
            last_error = str(exc)
            logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}: {last_error}")
            if bind_ip is not None:
                try:
                    lwip_close(wifi_dut, socket_fd=sock)
                except Exception:
                    pass
                sock = lwip_socket_create(
                    wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
                lwip_bind(wifi_dut, socket_fd=sock, ip_address=bind_ip, port=server_port)
            if count + 1 < retries:
                time.sleep(retry_delay_s)
    assert False, f"Socket connection failed in DUT: {last_error}"


class SnifferValidationProcess:

    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None, ap_mac_address=None,
                 sniffer_filter=None, siwx3xx_collections=None, test_case=None, power_save=None):
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.siwx3xx_collections = siwx3xx_collections
        self.test_case = test_case
        self.power_save = power_save if power_save is not None else WifiJoinThread.get_harness_power_save()

    def _with_ps_poll(self, filters_name):
        """PS-Poll frames only exist on air when the harness enabled power save."""
        if not self.power_save:
            logger().info("Power save disabled from Harness: skipping ps_poll sniffer check")
            return filters_name
        filters_name[max(filters_name) + 1] = 'ps_poll'
        return filters_name

    def verify_sniffer_validation(self):

        if self.test_case == 19347 or self.test_case == 19348:
            filters_name = None
            device_address = {'sa_addr': self.dut_mac_address, 'da_addr': self.ap_mac_address,
                              'ta_addr': self.dut_mac_address, 'ra_addr': self.ap_mac_address}

            if self.test_case == 19347:
                filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response',
                                3: 'dhcp_4_way_handshake_packets', 4: 'tcp_syn_with_syn_ack_with_ack'}

            if self.test_case == 19348:
                filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response',
                                3: 'dhcp_4_way_handshake_packets'}

            filters_name = self._with_ps_poll(filters_name)

            output = self.siwx3xx_collections.sniffer_validation_for_packet_filters(
                self.wifi_sniffer, self.sniffer_filter, device_address, filters_name=filters_name)

            logger().info(f'\n OUTPUT 1 = {output}\n')
            assert all(output.values()), 'Unable to find expected filter'

        if self.test_case == 19349 or self.test_case == 19350 or self.test_case == 19352:
            device_address_list = {'sa_addr': self.dut_mac_address, 'da_addr': self.ap_mac_address}

            filters_name_list = self._with_ps_poll({1: 'probe_req_response'})

            result = self.siwx3xx_collections.sniffer_validation_for_packet_filters(
                self.wifi_sniffer, self.sniffer_filter, device_address_list, filters_name=filters_name_list)

            logger().info(f'\n OUTPUT RESULT = {result}\n')
            assert all(result.values()), 'Unable to find expected filter'


class DataTransfer:
    def __init__(self):
        self.thread_lock = threading.Lock()
        self.sent_data = 0
        self.rcv_data = 0

    def send_and_receive_data_socket(
            self, thread_no, remote_socket, no_of_pkts, data_size, time_interval, wifi_dut, server_sock, local_port,
            server_ip,
            proto_type=0):

        proto_name = "TCP" if proto_type == 0 else "UDP"
        logger().info(f"[Thread {thread_no}] ========================================")
        logger().info(f"[Thread {thread_no}] Starting {proto_name} data transfer")
        logger().info(f"[Thread {thread_no}] Socket: {server_sock}, Packets: {no_of_pkts}, Size: {data_size} bytes")
        logger().info(f"[Thread {thread_no}] Server: {server_ip}:{local_port}, Interval: {time_interval}s")
        logger().info(f"[Thread {thread_no}] ========================================")

        payload = "A" * data_size
        bytes_sent = 0
        for _ in range(no_of_pkts):
            if proto_type == 0:
                lwip_send(wifi_dut, socket_fd=server_sock, data=payload, higher_data_len=1)
            else:
                lwip_send_to(
                    wifi_dut, socket_fd=server_sock, data=payload,
                    ip_address=server_ip, port=local_port)
            bytes_sent += data_size
        logger().info(f"[Thread {thread_no}] **** Sent {bytes_sent} bytes from DUT ****")

        timeout = 2
        if proto_type == 0:
            remote_socket.set_recv_timeout(socket_type=0, timeout=timeout)
        else:
            remote_socket.set_recv_timeout(socket_type=1, use_client_socket=True, timeout=timeout)

        for i in range(0, no_of_pkts):
            if proto_type == 0:
                data = remote_socket.recv_data_tcp(data_size, timeout=timeout)
                if i % 10 == 0 or i == 0:  # Log every 10th packet
                    logger().info(
                        f'[Thread {thread_no}] TCP RX packet {i + 1}/{no_of_pkts}, size: {len(data) if isinstance(data, str) else 0} bytes')
            else:
                data, address = remote_socket.recv_data_udp(data_size, timeout=timeout)
                if i % 10 == 0 or i == 0:  # Log every 10th packet
                    logger().info(
                        f'[Thread {thread_no}] UDP RX packet {i + 1}/{no_of_pkts}, size: {len(data) if isinstance(data, str) else 0} bytes')

            if not isinstance(data, str):
                logger().warning(
                    f"[Thread {thread_no}] **** Unable to Receive on Socket: {server_sock} at packet {i + 1} ****")
                break
            self.rcv_data = self.rcv_data + len(data)
            if self.rcv_data == bytes_sent:
                break

        remote_socket.socket_close_indication(1)

        logger().info(f"[Thread {thread_no}] ========================================")
        logger().info(f"[Thread {thread_no}] {proto_name} DATA TRANSFER COMPLETE")
        logger().info(f"[Thread {thread_no}] Total bytes received: {self.rcv_data} / {bytes_sent}")

        if proto_type == 0:
            logger().info(f"[Thread {thread_no}] ========================================")
            assert self.rcv_data == int(
                bytes_sent), f"Data transfer failed. Expected {bytes_sent} bytes but received {self.rcv_data} bytes"
        else:
            packet_loss = 100 - (int(self.rcv_data) * 100 / int(bytes_sent)) if int(bytes_sent) > 0 else 0
            logger().info(f"[Thread {thread_no}] UDP packet loss: {packet_loss:.2f}%")
            logger().info(f"[Thread {thread_no}] ========================================")


class WifiJoinThread(ThreadBase):
    IP_CONFIG_TIMEOUT_S = 120
    INVALID_IPV4 = "0.0.0.0"
    LWIP_SETTLE_S = 5
    PING_RETRY_COUNT = 3
    PEER_IFACE_CANDIDATES = ("eth1", "eth0", "wlan0", "wlan1")
    # lwIP reports bsd error 105 (ENOBUFS) once more than this many fds are open.
    LWIP_MAX_CONCURRENT_SOCKETS = 4

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, sniffer_filter=None, wifi_sniffer=None,
                 siwx3xx_collections=None, test_name=None, remote_socket_factory=None, ap_mac_address=None,
                 remote_socket=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.siwx3xx_collections = siwx3xx_collections
        self.test_name = test_name
        self.dut_addr = None
        self.device_ip = None
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.enc = "ccmp"
        self.remote_socket_factory = remote_socket_factory
        self.remote_socket = remote_socket
        self.power_save = self.get_harness_power_save()
        self.peer_iface = None
        self.peer_ip = None

    @staticmethod
    def get_harness_power_save():
        """Read the user-defined power_save flag from the UTF harness wifi defaults."""
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(
            f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        return power_save

    @staticmethod
    def enable_dut_power_save(wifi_dut, mode="power_save_low_latency"):
        wifi_dut.interfaces.wifi.set_performance_profile(mode=mode)
        wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Siwx3xxPowerSaveModes.PowerSaveMode2,
            psp_type=Siwx3xxPowerSaveProcedureTypes.FastPowerSave,
        )

    def maybe_enable_dut_power_save(self):
        """Enable DUT power save only when the harness flag is set."""
        if self.power_save:
            self.enable_dut_power_save(self.wifi_dut)
            return True
        logger().info("Skipping DUT power save; harness power_save flag is not set")
        return False

    @staticmethod
    def join_encryption(security_name, configured_enc):
        """An Open AP must join with SL_WIFI_NO_ENCRYPTION; the stored profile that
        net.up consumes otherwise advertises a cipher the AP never negotiates."""
        if security_name == "open":
            return "open"
        return configured_enc

    def peer_interface_on_dut_subnet(self, subnet):
        """Whichever peer interface actually holds an address on the DUT subnet, so a
        stale harness 'interface' value costs a log line instead of the whole run."""
        wifi = self.wifi_client.interfaces.wifi
        for candidate in self.PEER_IFACE_CANDIDATES:
            try:
                candidate_ip = str(wifi.get_ip_address(network_interface=candidate))
            except Exception:
                continue
            if candidate_ip.rsplit(".", 1)[0] == subnet:
                logger().warning(
                    f"\n **** Harness wifi_client interface has no address on the DUT "
                    f"subnet; using '{candidate}' ({candidate_ip}) instead ****")
                return candidate, candidate_ip
        return None, None

    def create_peer_socket(self):
        """Listen on the same NIC the DUT will dial (factory defaults to eth0)."""
        iface = self.peer_iface or "eth1"
        logger().info(f"Peer listen socket on interface={iface}")
        return self.remote_socket_factory.interfaces.socket.create_socket(interface=iface)

    def peer_server_ip(self):
        """Remote peer address the DUT dials. The peer must sit on the joined AP's
        subnet, otherwise every lwip.connect ends in errno 103/107."""
        if self.wifi_client is None:
            raise RuntimeError(
                "wifi_client was not passed into WifiJoinThread; peer IP cannot be resolved")
        wifi = self.wifi_client.interfaces.wifi
        iface = wifi.config.get("interface", "wlan0")
        ssid = self.wifi_access_point.interfaces.wifi.ssid
        dut_ip = (self.dut_addr or {}).get("device_ip")
        subnet = dut_ip.rsplit(".", 1)[0] if dut_ip else None

        server_ip = None
        reason = None
        try:
            server_ip = str(wifi.get_ip_address())
        except RuntimeError as exc:
            reason = str(exc)

        if subnet and (server_ip is None or server_ip.rsplit(".", 1)[0] != subnet):
            fallback_iface, fallback_ip = self.peer_interface_on_dut_subnet(subnet)
            if fallback_ip:
                self.peer_iface = fallback_iface
                self.peer_ip = fallback_ip
                return fallback_ip

        if server_ip is None:
            raise RuntimeError(
                f"wifi_client has no IPv4 on '{iface}' ({reason}) and no other "
                f"interface is on the DUT subnet; join the peer to '{ssid}' or point "
                f"the harness wifi_client at the interface facing that AP")
        if subnet and server_ip.rsplit(".", 1)[0] != subnet:
            logger().warning(
                f"\n **** Remote peer {server_ip} ({iface}) is not on the DUT subnet "
                f"({dut_ip}); the DUT cannot reach the socket server. Connect "
                f"wifi_client to '{ssid}' ****")
        self.peer_iface = iface
        self.peer_ip = server_ip
        return server_ip

    def lwip_sta_join_and_get_ip(self, retry_count=3):
        """Bring up STA + lwIP IP with the required DUT sequence:

        wifi.client.connect ... -z 1  (enable_lwip)
        net.up client
        lwip.print_device_ip client -p ipv4
        """
        wifi = self.wifi_dut.interfaces.wifi
        ap = self.wifi_access_point.interfaces.wifi
        timeout = self.IP_CONFIG_TIMEOUT_S
        if self.siwx3xx_collections is not None and not wifi.associated:
            scan_status, reason = self.siwx3xx_collections.scan(
                self.wifi_dut, scan_status=False, retry_count=retry_count)
            assert scan_status, f"....Scanning for AP failed..with reason: {reason}...."

        dut_mac = wifi.get_mac_address()
        security = ap.security.name.lower()
        if not wifi.associated:
            enc = self.join_encryption(security, self.enc)
            logger().info(
                f"wifi.client.connect ssid={ap.ssid} enable_lwip=1 (-z 1) security={security} enc={enc}")
            wifi.join(
                ssid=ap.ssid,
                passphrase=ap.passphrase,
                security=security,
                channel=ap.channel,
                enc=enc,
                enable_lwip=1,
                timeout=60,
            )
            wifi.associated = True

        net_up_ok = False
        last_error = None
        for attempt in range(1, retry_count + 1):
            try:
                logger().info(f"net.up client (attempt {attempt}/{retry_count})")
                wifi.sl_net_up(mode="client", timeout=timeout)
                net_up_ok = True
                break
            except Exception as exc:
                last_error = str(exc)
                logger().info(f"net.up failed: {last_error}")
                # A half-way net.up leaves the lwIP netif attached; tear it down so
                # the next attempt starts from a clean interface.
                try:
                    wifi.sl_net_down(mode="client")
                except Exception as down_exc:
                    logger().info(f"net.down after failed net.up: {down_exc}")
        assert net_up_ok, f"net.up client failed: {last_error}"

        ip_config = wifi.display_device_ip_lwip(mode="client", ip_version="ipv4", timeout=timeout)
        device_ip = wifi.get_device_ip(ip_config)
        logger().info(f"lwIP DUT IP: {device_ip}")
        assert device_ip and device_ip != self.INVALID_IPV4, (
            f"lwIP reported unusable IP {device_ip} after net.up")
        # The lwIP netif does not answer ARP for the first few seconds after net.up.
        logger().info(f"Waiting {self.LWIP_SETTLE_S}s for the lwIP netif to settle")
        time.sleep(self.LWIP_SETTLE_S)
        return {"device_ip": device_ip, "dut_mac_address": dut_mac}

    def run(self):
        try:
            self.dut_addr = self.lwip_sta_join_and_get_ip()
            logger().info(
                f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")
            ping_ok = self.siwx3xx_collections.ping(
                device_ip=self.dut_addr["device_ip"], ping_count=10,
                retry_count=self.PING_RETRY_COUNT)
            assert ping_ok, "DUT NOT RESPONDING FOR PING REQUEST......"

            if self.maybe_enable_dut_power_save():
                logger().info("....Pinging DUT after power-save....")
                ping_ok = self.siwx3xx_collections.ping(
                    device_ip=self.dut_addr["device_ip"], ping_count=10,
                    retry_count=self.PING_RETRY_COUNT)
                assert ping_ok, "DUT NOT RESPONDING FOR PING REQUEST......"

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

    def tcp_server_single_socket(self, port=5001, keepalive_time=60, server_ip=None, data_length=1000):
        logger().info(f"\n Starting the Remote Socket Server \n")
        self.remote_socket.interfaces.socket.start_server(port=port)
        socket_id = lwip_socket_create(self.wifi_dut)
        lwip_bind(self.wifi_dut, socket_fd=socket_id, ip_address=self.dut_addr['device_ip'], port=port)
        logger().info(f"Setting the socket option SO_KEEPALIVE with {keepalive_time} seconds")
        lwip_set_opt(
            self.wifi_dut, socket_fd=socket_id, option_level="SOL_SOCKET",
            option_name="SO_KEEPALIVE", option_value=keepalive_time)
        logger().info("DUT is connecting to server socket")
        lwip_tcp_connect_with_retry(self.wifi_dut, socket_id, server_ip, port, retry_delay_s=0)
        sent_data = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=data_length)
        )
        try:
            lwip_send(self.wifi_dut, socket_fd=socket_id, data=sent_data, higher_data_len=1)
            received_data = (
                self.remote_socket.interfaces.socket.recv_data_tcp(len(sent_data))
            )
            logger().info(f"\nReceived Data: {received_data}\n")
            assert (
                    sent_data == received_data
            ), f"Data mismatch in sent and received data"
        except Exception as e:
            logger().info(
                f"Socket Data Transfer Failed Within Duration"
            )
        time.sleep(keepalive_time * 1.3)
        lwip_close(self.wifi_dut, socket_fd=socket_id)
        logger().info(f"Stopping the Remote Socket Server")
        self.remote_socket.interfaces.socket.stop()

    def tcp_multiple_socket_dut_client(self):
        no_of_pkts = 100
        pkt_length = 1460

        server_ip = self.peer_server_ip()

        client_sockets = []
        server_port_base = 5001
        server_socks = []
        socket_count = self.LWIP_MAX_CONCURRENT_SOCKETS
        dut_ip = self.dut_addr['device_ip']
        for count in range(0, socket_count):
            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')

            client_socket = self.create_peer_socket()
            client_sockets.append(client_socket)
            client_socket.start_server(port=local_port)

            sock = lwip_socket_create(
                self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
            lwip_bind(
                self.wifi_dut, socket_fd=sock, ip_address=dut_ip, port=local_port)

            logger().info("********** DUT connecting to server **********")
            sock = lwip_tcp_connect_with_retry(
                self.wifi_dut, sock, server_ip, local_port, bind_ip=dut_ip)
            server_socks.append(sock)
            time.sleep(1)

        server_port = 5001
        time_interval = 5
        data_transfer_objs = []
        socket_threads = []

        logger().info("=" * 80)
        logger().info(f"STARTING DATA TRANSFER ON {len(server_socks)} TCP SOCKETS")
        logger().info("=" * 80)

        for count in range(0, socket_count):
            logger().info(f"Creating data transfer thread {count} for socket {server_socks[count]}")
            local_port = server_port + count
            data_transfer_objs.append(DataTransfer())

            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(
                                             count, client_sockets[count], no_of_pkts, pkt_length, time_interval,
                                             self.wifi_dut,
                                             server_socks[count], local_port, server_ip, 0),
                                         daemon=True,
                                         name=f"DataTransfer-Socket{count}"))

        # Start all threads
        logger().info("Starting all data transfer threads...")
        for idx, thread in enumerate(socket_threads):
            thread.start()
            logger().info(f"Started thread {idx}: {thread.name}")
            time.sleep(2)

        # Wait for all threads to complete with timeout
        logger().info("Waiting for all threads to complete...")
        all_completed = True
        for idx, thread in enumerate(socket_threads):
            thread.join(timeout=60)  # 60 second timeout per thread
            if thread.is_alive():
                logger().error(f"Thread {idx} ({thread.name}) did not complete within timeout!")
                all_completed = False
            else:
                logger().info(f"Thread {idx} ({thread.name}) completed successfully")

        if all_completed:
            logger().info("=" * 80)
            logger().info("ALL DATA TRANSFER THREADS COMPLETED SUCCESSFULLY")
            logger().info("=" * 80)
        else:
            logger().error("=" * 80)
            logger().error("SOME DATA TRANSFER THREADS DID NOT COMPLETE!")
            logger().error("=" * 80)

        for sock in server_socks:
            logger().info(f"Closing socket_id->{sock}")
            lwip_close(self.wifi_dut, socket_fd=sock)

    def udp_multiple_socket_dut_client(self):
        server_ip = self.peer_server_ip()

        no_of_pkts = 100
        pkt_length = 1460
        local_port_udp = 8001
        time_interval = 5

        for count in range(0, 10):
            local_port = local_port_udp + count
            client_socket = self.create_peer_socket()
            client_socket.start_server(port=local_port, socket_type=1)

            sock = lwip_socket_create(
                self.wifi_dut, domain="AF_INET", sock_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            logger().info(f"Successfully opened udp client socket and socket id received is {sock} which is expected")
            lwip_bind(
                self.wifi_dut, socket_fd=sock, ip_address=self.dut_addr['device_ip'], port=local_port)

            logger().info(f"Iteration: {count}")
            DataTransfer().send_and_receive_data_socket(
                count + 1, client_socket, no_of_pkts, pkt_length, time_interval,
                self.wifi_dut, sock, local_port, server_ip, 1)
            lwip_close(self.wifi_dut, socket_fd=sock)
            try:
                client_socket.stop()
            except Exception:
                pass

    def udp_single_socket_dut_client(self):
        no_of_pkts = 100
        pkt_length = 1460
        server_port = 8001
        local_port_udp = 8001

        time_interval = 5

        data_transfer_objs = []
        socket_threads = []
        server_socks = []
        client_sockets = []

        # This function is responsible to create UDP socket, send data to the server
        server_ip = self.peer_server_ip()

        for count in range(0, 1):
            local_port = local_port_udp + count
            client_socket = self.create_peer_socket()
            client_sockets.append(client_socket)
            client_socket.start_server(port=local_port, socket_type=1)

            sock = lwip_socket_create(
                self.wifi_dut, domain="AF_INET", sock_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            logger().info(f"Successfully opened udp client socket and socket id received is {sock} which is expected")
            server_socks.append(sock)

            lwip_bind(
                self.wifi_dut, socket_fd=sock, ip_address=self.dut_addr['device_ip'], port=local_port)

        for count in range(0, 1):
            logger().info(f"Iteration: {count}")
            local_port = server_port + count
            data_transfer_objs.append(DataTransfer())

            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(
                                             count + 1, client_sockets[count], no_of_pkts, pkt_length, time_interval,
                                             self.wifi_dut,
                                             server_socks[count], local_port, server_ip, 1), daemon=True))

            socket_threads[count].start()
            socket_threads[count].join()

        for sock in server_socks:
            logger().info(f"Closing socket_id->{sock}")
            lwip_close(self.wifi_dut, socket_fd=sock)

    def tcp_single_socket_dut_client(self):
        no_of_pkts = 100
        pkt_length = 1460
        client_sockets = []
        server_port_base = 5001
        server_socks = []

        server_ip = self.peer_server_ip()

        for count in range(0, 1):
            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')

            client_socket = self.create_peer_socket()
            client_sockets.append(client_socket)
            client_socket.start_server(port=local_port)

            sock = lwip_socket_create(
                self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
            server_socks.append(sock)

            lwip_bind(
                self.wifi_dut, socket_fd=sock, ip_address=self.dut_addr['device_ip'], port=local_port)

            logger().info("********** DUT connecting to server **********")
            sock = lwip_tcp_connect_with_retry(
                self.wifi_dut, sock, server_ip, local_port, retry_delay_s=0,
                bind_ip=self.dut_addr['device_ip'])
            server_socks[-1] = sock
            time.sleep(1)

        server_port = 5001
        time_interval = 5
        data_transfer_objs = []
        socket_threads = []
        for count in range(0, 1):
            logger().info(f"Iteration: {count}")
            local_port = server_port + count
            data_transfer_objs.append(DataTransfer())

            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(
                                             count + 1, client_sockets[count], no_of_pkts, pkt_length, time_interval,
                                             self.wifi_dut,
                                             server_socks[count], local_port, server_ip, 0), daemon=True))

            socket_threads[count].start()
            socket_threads[count].join()

        for sock in server_socks:
            logger().info(f"Closing socket_id->{sock}")
            lwip_close(self.wifi_dut, socket_fd=sock)

    def tcp_udp_multiple_socket_dut_client(self):
        no_of_pkts = 100
        pkt_length = 1460
        client_sockets = []
        server_port_base = 8001
        server_socks = []

        server_ip = self.peer_server_ip()

        half = max(1, self.LWIP_MAX_CONCURRENT_SOCKETS // 2)
        dut_ip = self.dut_addr['device_ip']

        for count in range(0, half):
            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')

            client_socket = self.create_peer_socket()
            client_sockets.append(client_socket)
            client_socket.start_server(port=local_port)

            sock = lwip_socket_create(
                self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
            lwip_bind(
                self.wifi_dut, socket_fd=sock, ip_address=dut_ip, port=local_port)

            logger().info("********** DUT connecting to server **********")
            sock = lwip_tcp_connect_with_retry(
                self.wifi_dut, sock, server_ip, local_port, bind_ip=dut_ip)
            server_socks.append(sock)
            time.sleep(1)

        local_port_udp = server_port_base + half
        for count in range(0, half):
            local_port = local_port_udp + count
            client_socket = self.create_peer_socket()
            client_sockets.append(client_socket)
            client_socket.start_server(port=local_port, socket_type=1)

            sock = lwip_socket_create(
                self.wifi_dut, domain="AF_INET", sock_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            logger().info(f"Successfully opened udp client socket and socket id received is {sock} which is expected")
            server_socks.append(sock)

            lwip_bind(
                self.wifi_dut, socket_fd=sock, ip_address=dut_ip, port=local_port)

        server_port = server_port_base
        time_interval = 5
        data_transfer_objs = []
        socket_threads = []
        for count in range(0, half * 2):
            prototype = 0 if count < half else 1
            logger().info(f"Iteration: {count}")
            local_port = server_port + count
            data_transfer_objs.append(DataTransfer())

            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(
                                             count + 1, client_sockets[count], no_of_pkts, pkt_length, time_interval,
                                             self.wifi_dut,
                                             server_socks[count], local_port, server_ip, prototype), daemon=True))

            socket_threads[count].start()
            socket_threads[count].join()

        for sock in server_socks:
            logger().info(f"Closing socket_id->{sock}")
            lwip_close(self.wifi_dut, socket_fd=sock)

    def tcp_remote_terminate(self):
        no_of_pkts = 100
        pkt_length = 1460
        local_port = 5001

        server_ip = self.peer_server_ip()
        self.remote_socket.interfaces.socket.start_server(port=local_port)
        self.wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        socket_id = lwip_socket_create(
            self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")

        lwip_bind(
            self.wifi_dut, socket_fd=socket_id, ip_address=self.dut_addr['device_ip'], port=local_port)

        logger().info("DUT is connecting to server socket")
        lwip_tcp_connect_with_retry(self.wifi_dut, socket_id, server_ip, local_port)
        time.sleep(5)

        bytes_sent = lwip_send_data_pkts(
            self.wifi_dut, socket_id=socket_id, pkt_length=pkt_length, no_of_pkts=no_of_pkts, time_interval=5,
            server_ip=server_ip, server_port=local_port)

        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        self.remote_socket.interfaces.socket.stop()
        event_data_output = ""
        time.sleep(5)
        events = self.wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.REMOTE_TERMINATE:
                event_data_output = event.event_data

        logger().info(f" ***************** EVENT DATA IS : {event_data_output} ********************** ")

        assert "Remote Terminate" in event_data_output, "expected error code not found. Expected is Remote Terminate"
        logger().info("*********** Remote Termination is Successful *************")

    def _enable_power_save(self):
        return self.maybe_enable_dut_power_save()

    @staticmethod
    def _per_socket_close_sockopt(wifi_dut, socket_fd):
        wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(
            socket_fd=socket_fd,
            option_name=Siwx3xxCustomSyncSockOptParms.SL_SI91X_SO_PER_SOCKET_CLOSE_ENABLE,
            cert_index=1,
        )

    def _close_remote_tcp_peer(self, remote_client):
        if remote_client.sock is not None:
            try:
                remote_client.sock.shutdown(socket.SHUT_RDWR)
                remote_client.sock.close()
            except Exception:
                pass
            remote_client.sock = None

    def _close_remote_tcp_peer_after_delay(self, remote_client, delay_sec):
        time.sleep(delay_sec)
        self._close_remote_tcp_peer(remote_client)

    def _connect_remote_tcp_ephemeral(self, remote_client, device_ip, dut_port, interface=None):
        """Bind remote client to ephemeral local port (avoid 5001 EADDRINUSE on test host)."""
        if interface:
            remote_client.interface = interface
        if remote_client.sock is not None:
            try:
                remote_client.sock.close()
            except Exception:
                pass
            remote_client.sock = None
        remote_client.connect_client_tcp(device_ip, dut_port, client_port=0)

    def _accept_server_with_remote_client(
            self, server_socket_id, remote_peer, server_ip, server_port,
            wlan_interface="wlan0", parallel_timeout=60, sync_accept=True):
        """Parallel accept + remote TCP connect on DUT AP server socket."""
        remote_peer.interface = wlan_interface
        if remote_peer.sock is not None:
            try:
                remote_peer.sock.close()
            except Exception:
                pass
            remote_peer.sock = None
        if sync_accept:
            logger().info(
                f"Sync accept fd {server_socket_id} + remote connect "
                f"{server_ip}:{server_port} on {wlan_interface}")
            ThreadBase.call_functions_simultaneously(
                [
                    (lwip_accept, self.wifi_dut, server_socket_id),
                    (remote_peer.connect_client_tcp, server_ip, server_port),
                ],
                timeout=parallel_timeout,
            )
            return
        accept_fn = partial(lwip_accept, self.wifi_dut, server_socket_id)
        logger().info(
            f"Async accept fd {server_socket_id} + remote connect "
            f"{server_ip}:{server_port} on {wlan_interface}")
        ThreadBase.call_functions_simultaneously(
            [
                (accept_fn,),
                (self._connect_remote_tcp_ephemeral, remote_peer, server_ip, server_port, wlan_interface),
            ],
            timeout=parallel_timeout,
        )

    def _verify_remote_terminate(self, since_time=None, expected_port=None):
        def _pick_remote_terminate_event(events):
            for event in reversed(events):
                event_data = event.event_data or ""
                if event.event_type != AsyncEventIdentifiers.REMOTE_TERMINATE and (
                        "Remote Terminate" not in event_data):
                    continue
                if expected_port is not None and f"port {expected_port}" not in event_data:
                    continue
                return event_data
            return ""

        event_data_output = ""
        time.sleep(5)
        sw = Stopwatch()
        while sw.elapsed_sec < 90 and not event_data_output:
            self.wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            if since_time is not None:
                events = self.wifi_dut.interfaces.wifi.get_async_events(
                    since_time=since_time, update_last_retrieved_timestamp=False)
            else:
                events = self.wifi_dut.interfaces.wifi.get_async_events(
                    update_last_retrieved_timestamp=False)
            event_data_output = _pick_remote_terminate_event(events)
            if not event_data_output:
                time.sleep(2)
        if not event_data_output and since_time is not None:
            self.wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            events = self.wifi_dut.interfaces.wifi.get_async_events(
                since_time=0, update_last_retrieved_timestamp=False)
            event_data_output = _pick_remote_terminate_event(events)
        logger().info(f"EVENT DATA: {event_data_output}")
        assert event_data_output, "Remote terminate event (0x62) not received from TA"
        assert "Remote Terminate" in event_data_output, "Expected Remote Terminate in event data"
        logger().info("Remote Termination is Successful")

    def _tcp_client_socket_connect(self, socket_id, server_ip, local_port=5001):
        lwip_bind(
            self.wifi_dut, socket_fd=socket_id, ip_address=self.dut_addr['device_ip'], port=local_port)
        lwip_tcp_connect_with_retry(self.wifi_dut, socket_id, server_ip, local_port)
        logger().info("Socket connection is successful")

    def tcp_per_socket_close_remote_terminate(self, no_of_pkts=100, pkt_length=1460, local_port=5001):
        """C1726572: WLAN+BLE TCP client TX, remote terminate (0x62), host close (0x43)."""
        self._enable_power_save()
        server_ip = self.peer_server_ip()
        self.remote_socket.interfaces.socket.start_server(port=local_port)
        self.wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        socket_id = lwip_socket_create(
            self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
        logger().info(f"Socket open successfully : {socket_id}")
        self._per_socket_close_sockopt(self.wifi_dut, socket_id)
        self._tcp_client_socket_connect(socket_id, server_ip, local_port)
        time.sleep(2)
        tx_thread = Thread(
            target=lwip_send_data_pkts,
            args=(self.wifi_dut, socket_id, pkt_length, no_of_pkts, 1, server_ip, local_port),
            daemon=True,
        )
        tx_thread.start()
        time.sleep(2)
        self.remote_socket.interfaces.socket.stop()
        tx_thread.join(timeout=120)
        self._verify_remote_terminate()
        lwip_close(self.wifi_dut, socket_fd=socket_id)
        logger().info("Host close completed after remote terminate")

    def tcp_per_socket_close_graceful_host_close(self, no_of_pkts=10, pkt_length=50, local_port=5001):
        """C1726579: TCP client TX then graceful host close (FIN not RST)."""
        self._enable_power_save()
        server_ip = self.peer_server_ip()
        self.remote_socket.interfaces.socket.start_server(port=local_port)
        socket_id = lwip_socket_create(
            self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
        self._per_socket_close_sockopt(self.wifi_dut, socket_id)
        self._tcp_client_socket_connect(socket_id, server_ip, local_port)
        send_ok = [SLStatus.SL_STATUS_OK, SLStatus.SL_STATUS_OBJECT_WRITE]
        bytes_sent_raw = lwip_send_data_pkts(
            self.wifi_dut, socket_id=socket_id, pkt_length=pkt_length, no_of_pkts=no_of_pkts,
            time_interval=30, server_ip=server_ip, server_port=local_port,
            expected_status=send_ok)
        logger().info(f"Number of bytes sent by dut {bytes_sent_raw}")
        lwip_close(self.wifi_dut, socket_fd=socket_id)
        self.remote_socket.interfaces.socket.socket_close_indication(1)
        self.wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
        logger().info("Graceful host close completed")
        self.remote_socket.interfaces.socket.stop()

    def tcp_per_socket_close_graceful_loop(self, loop_duration_sec=24 * 3600, no_of_pkts=20, pkt_length=50,
                                           local_port=5001):
        """C1726584: repeat socket/connect/send/graceful close for loop_duration_sec."""
        self._enable_power_save()
        loop_sw = Stopwatch()
        iteration = 0
        while loop_sw.elapsed_sec < loop_duration_sec:
            iteration += 1
            logger().info(f"Graceful close loop iteration {iteration}, elapsed {loop_sw.elapsed_sec:.0f}s")
            try:
                self.remote_socket.interfaces.socket.stop()
            except Exception:
                pass
            self.tcp_per_socket_close_graceful_host_close(
                no_of_pkts=no_of_pkts, pkt_length=pkt_length, local_port=local_port)
            time.sleep(1)
        logger().info(f"Loop completed: {iteration} iterations")

    def tcp_multi_server_per_socket_close_remote_terminate(self, num_sockets=10, local_port=5001):
        """C1726574: multi TCP server RX, remote terminate on one socket, host close."""
        self._enable_power_save()
        device_ip = self.dut_addr['device_ip']
        # Use init-time socket pool (same as C19351). Custom set_socket_config
        # with total_sockets=20 fails with 0x1FF6D (INVALID_SOCKET_CONFIG_PARAMS).
        server_socket_ids = []
        client_socket_ids = []
        remote_clients = []
        for socket_index in range(num_sockets):
            dut_port = local_port + socket_index
            logger().info(
                f"C1726574 socket {socket_index}: DUT server port {dut_port}")
            server_socket_id = lwip_socket_create(
                self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
            server_socket_ids.append(server_socket_id)
            self._per_socket_close_sockopt(self.wifi_dut, server_socket_id)
            lwip_bind(
                self.wifi_dut, socket_fd=server_socket_id, ip_address=device_ip, port=dut_port)
            lwip_listen(self.wifi_dut, socket_fd=server_socket_id, backlog=1)
            remote_client = self.create_peer_socket()
            ThreadBase.call_functions_simultaneously(
                [
                    (lwip_accept, self.wifi_dut, server_socket_id),
                    (self._connect_remote_tcp_ephemeral, remote_client, device_ip, dut_port),
                ],
                timeout=60,
            )
            assert remote_client.sock is not None, (
                f"Remote client not connected on DUT port {dut_port}")
            client_socket_ids.append(server_socket_id + 1)
            remote_clients.append(remote_client)
            tx_buffer = "X" * 50
            remote_client.send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(
                socket_fd=server_socket_id + 1, timeout=60, async_timeout=60)
            logger().info(
                f"C1726574 socket {socket_index}: RX complete on DUT fd {server_socket_id + 1}")
        for socket_index in range(1, num_sockets):
            logger().info(f"C1726574 closing socket {socket_index} (port {local_port + socket_index})")
            self._close_remote_tcp_peer(remote_clients[socket_index])
            for sid in (client_socket_ids[socket_index], server_socket_ids[socket_index]):
                try:
                    lwip_close(self.wifi_dut, socket_fd=sid)
                except Exception:
                    pass
        self.wifi_dut.interfaces.wifi.bsdAsyncEvent(time=5)
        time.sleep(2)
        remote_client = remote_clients[0]
        client_socket_id = client_socket_ids[0]
        server_socket_id = server_socket_ids[0]
        assert remote_client.sock is not None, (
            "Remote client on port 5001 is not connected before remote terminate")
        logger().info(
            f"C1726574 remote terminate on DUT accepted fd {client_socket_id} "
            f"(listen fd {server_socket_id}, local port {local_port})")
        # Per-socket close sockopt applies to listen fd 0 only (set in setup loop).
        # Accepted sync fd 1 returns errno 22 (EINVAL) for SL_SI91X_SO_PER_SOCKET_CLOSE.
        self.wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        since_time = time.perf_counter_ns()
        no_of_pkts = 100
        pkt_length = 1460
        peer_ip = None
        if self.wifi_client:
            try:
                peer_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            except Exception:
                pass
        # Match C1726587: TX thread + remote peer close (no bsd_socket.select — fails
        # on accepted sync fd 1 with errno 0 / SL_STATUS_FAIL in multi-server setup).
        tx_thread = Thread(
            target=lwip_send_data_pkts,
            args=(self.wifi_dut, client_socket_id, pkt_length, no_of_pkts, 30, peer_ip, 0),
            daemon=True,
        )
        close_thread = Thread(
            target=self._close_remote_tcp_peer_after_delay,
            args=(remote_client, 0.3),
            daemon=True,
        )
        tx_thread.start()
        close_thread.start()
        tx_thread.join(timeout=120)
        close_thread.join(timeout=30)
        self._verify_remote_terminate(since_time=since_time)
        lwip_close(self.wifi_dut, socket_fd=client_socket_id)
        lwip_close(self.wifi_dut, socket_fd=server_socket_id)

    def tls_per_socket_close_remote_terminate(self, ssl_server, no_of_pkts=100, pkt_length=1460, local_port=5001):
        """C1726576: TLS client TX, remote terminate (0x62), host close."""
        self._enable_power_save()
        self.wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        ssl_port = ssl_server.interfaces.ssl.config["device_port1"]
        ssl_server.interfaces.ssl.start_server(port=ssl_port)
        server_ip = ssl_server.interfaces.ssl.server_ip
        socket_id = lwip_socket_create(
            self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
        logger().info(f"Socket open successfully : {socket_id}")
        self._per_socket_close_sockopt(self.wifi_dut, socket_id)
        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
            socket_fd=socket_id, option_name="TCP_ULP", option_val="tls_1_2")
        lwip_bind(
            self.wifi_dut, socket_fd=socket_id, ip_address=self.dut_addr['device_ip'], port=local_port)
        self.wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=socket_id, cert_index=0)
        lwip_tcp_connect_with_retry(self.wifi_dut, socket_id, server_ip, ssl_port)
        logger().info("TLS socket connection is successful")
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            if ssl_server.interfaces.ssl.socket_connection_status(1):
                break
            time.sleep(1)
        assert ssl_server.interfaces.ssl.socket_connection_status(1), (
            "SSL server did not accept DUT TLS connection")
        time.sleep(2)
        since_time = time.perf_counter_ns()
        tx_thread = Thread(
            target=lwip_send_data_pkts,
            args=(self.wifi_dut, socket_id, pkt_length, no_of_pkts, 1, server_ip, ssl_port),
            daemon=True,
        )
        tx_thread.start()
        time.sleep(2)
        ssl_server.interfaces.ssl.stop_server()
        tx_thread.join(timeout=120)
        self._verify_remote_terminate(since_time=since_time)
        lwip_close(self.wifi_dut, socket_fd=socket_id)
        logger().info("Host close completed after remote terminate")

    def tls_per_socket_close_send_data(self, ssl_server, no_of_pkts=10, pkt_length=1370, local_port=5001):
        """C1726581: TLS client — per-socket close, TCP_ULP, connect, send."""
        self._enable_power_save()
        ssl_port = ssl_server.interfaces.ssl.config["device_port1"]
        ssl_server.interfaces.ssl.start_server(port=ssl_port)
        server_ip = ssl_server.interfaces.ssl.server_ip
        socket_id = lwip_socket_create(
            self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
        self._per_socket_close_sockopt(self.wifi_dut, socket_id)
        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
            socket_fd=socket_id, option_name="TCP_ULP", option_val="tls_1_2")
        lwip_bind(
            self.wifi_dut, socket_fd=socket_id, ip_address=self.dut_addr['device_ip'], port=local_port)
        self.wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=socket_id, cert_index=0)
        lwip_connect(self.wifi_dut, socket_fd=socket_id, ip_address=server_ip, port=ssl_port)
        if ssl_server.interfaces.ssl.config.get("type") == "ssl.server.ssl_linux":
            ssl_server.interfaces.ssl.data_receive(1, no_of_pkts, pkt_length)
        send_ok = [SLStatus.SL_STATUS_OK, SLStatus.SL_STATUS_OBJECT_WRITE]
        bytes_sent_raw = lwip_send_data_pkts(
            self.wifi_dut, socket_id=socket_id, pkt_length=pkt_length, no_of_pkts=no_of_pkts,
            time_interval=30, expected_status=send_ok)
        logger().info(f"TLS bytes sent: {bytes_sent_raw}")
        lwip_close(self.wifi_dut, socket_fd=socket_id)
        ssl_server.interfaces.ssl.stop_server()

    def tcp_per_socket_close_lan_unplug(self, no_of_pkts=100, pkt_length=1460, local_port=5001):
        """C1726585: TCP client TX, remote LAN unplug during send, socket close."""
        self._enable_power_save()
        server_ip = self.peer_server_ip()
        self.remote_socket.interfaces.socket.start_server(port=local_port)
        self.wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        socket_id = lwip_socket_create(
            self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
        self._per_socket_close_sockopt(self.wifi_dut, socket_id)
        self._tcp_client_socket_connect(socket_id, server_ip, local_port)
        iface = self.wifi_client.interfaces.wifi.config.get("interface", "eth0")
        tx_thread = Thread(
            target=lwip_send_data_pkts,
            args=(self.wifi_dut, socket_id, pkt_length, no_of_pkts, 1, server_ip, local_port),
            daemon=True,
        )
        tx_thread.start()
        time.sleep(2)
        logger().info(f"Plug out LAN cable — sudo ifconfig {iface} down")
        self.wifi_client.interfaces.wifi.shell(f"sudo ifconfig {iface} down")
        tx_thread.join(timeout=120)
        self._verify_remote_terminate()
        lwip_close(self.wifi_dut, socket_fd=socket_id)
        try:
            self.wifi_client.interfaces.wifi.shell(f"sudo ifconfig {iface} up")
        except Exception:
            pass
        self.remote_socket.interfaces.socket.stop()

    def tcp_ap_per_socket_close_remote_terminate(self, wifi_client, siwx3xx_collections,
                                                 no_of_pkts=100, pkt_length=1460, local_port=5001):
        """C1726587: DUT AP + Pi STA, TCP client remote terminate + host close."""
        channel = wifi_client.interfaces.wifi.config.get("channel", 11)
        ssid = wifi_client.interfaces.wifi.config.get("ssid", "WLAN_BLE_AP_C1726587")
        password = wifi_client.interfaces.wifi.config.get("passphrase", "12345678")
        security = wifi_client.interfaces.wifi.config.get("security", "WPA2")
        ping_count = UtfConfig.instance().defaults.get("wifi", {}).get("ping_count", 4)
        # AP+STA: power save before/after start_ap can fail association (same as C1726589).
        logger().info("C1726587: power save skipped in DUT AP mode")
        siwx3xx_collections.configure_dut_in_static_ip(
            self.wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
            static_gateway="192.168.100.76")
        try:
            wifi_client.interfaces.wifi.leave()
        except Exception:
            pass
        time.sleep(2)
        dut_addr = siwx3xx_collections.ap_mode_clients_connection(
            self.wifi_dut, [wifi_client], channel=channel, ssid=ssid, security=security,
            password=password, dtim_count=1, beacon_interval=100, ping_count=ping_count,
            no_of_clients=1, leave=False)
        dut_ip = dut_addr["dut_ip"]
        client_ip = dut_addr.get("client_ip")
        ping_ok = False
        for attempt in range(3):
            try:
                if wifi_client.interfaces.wifi.ping(
                        server_ip=dut_ip, num_ping_attempts=ping_count) < 5:
                    ping_ok = True
                    break
            except Exception as exc:
                logger().info(f"C1726587: ping to {dut_ip} attempt {attempt + 1} failed: {exc}")
            time.sleep(2)
        assert ping_ok, f"Pi cannot reach DUT AP IP {dut_ip} on wlan0 before TCP connect"
        remote_peer = self.remote_socket.interfaces.socket
        remote_peer.interface = wifi_client.interfaces.wifi.config.get("interface", "wlan0")
        remote_peer.start_server(port=local_port)
        server_ip = remote_peer.hostname_or_ip_address() or client_ip
        server_port = remote_peer.server_port or local_port
        logger().info(
            f"C1726587: remote TCP server on {server_ip}:{server_port} (interface={remote_peer.interface})")
        self.wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        socket_id = lwip_socket_create(
            self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
        self._per_socket_close_sockopt(self.wifi_dut, socket_id)
        lwip_bind(
            self.wifi_dut, socket_fd=socket_id, ip_address=dut_ip, port=server_port)
        lwip_tcp_connect_with_retry(self.wifi_dut, socket_id, server_ip, server_port)
        tx_thread = Thread(
            target=lwip_send_data_pkts,
            args=(self.wifi_dut, socket_id, pkt_length, no_of_pkts, 1, server_ip, server_port),
            daemon=True,
        )
        tx_thread.start()
        time.sleep(2)
        remote_peer.stop()
        tx_thread.join(timeout=120)
        self._verify_remote_terminate(expected_port=server_port)
        lwip_close(self.wifi_dut, socket_fd=socket_id)

    def tcp_concurrent_per_socket_close_remote_terminate(
            self, wifi_access_point, wifi_client, siwx3xx_collections, remote_socket,
            no_of_pkts=1, pkt_length=50, local_port=5001):
        """C1726589: concurrent STA+AP — server RX then client TX with remote terminate."""
        ap_ssid = self.wifi_dut.interfaces.wifi.config.get("ssid", "WLAN_BLE_AP_C1726589")
        channel = wifi_client.interfaces.wifi.config.get("channel", 11)
        password = wifi_client.interfaces.wifi.config.get("passphrase", "12345678")
        ping_count = UtfConfig.instance().defaults.get("wifi", {}).get("ping_count", 4)
        # Concurrent STA+AP rejects power save (0x10074 before start_ap, 0x10021 after),
        # so this case stays on power_save=False regardless of the harness flag.
        dut_sta = siwx3xx_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut, wifi_access_point=wifi_access_point, retry_count=3,
            associated=self.wifi_dut.interfaces.wifi.associated, ping_after_power_save=False,
            power_save=False, enc="ccmp")
        sta_ip = dut_sta["device_ip"]
        siwx3xx_collections.configure_dut_in_static_ip(
            self.wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
            static_gateway="192.168.100.76")
        try:
            wifi_client.interfaces.wifi.leave()
        except Exception:
            pass
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.start_ap(
            ssid=ap_ssid, security="WPA2", psk=password, channel=channel,
            dtim_beacon_count=1, beacon_interval=100)
        time.sleep(3)
        wifi_client.interfaces.wifi.join(
            ssid=ap_ssid, security=SecurityMode.WPA2, passphrase=password,
            country="US", scan_ssid=1)
        time.sleep(10)
        # Concurrent STA+AP: PS before start_ap → 0x10074; PS after start_ap → 0x10021.
        # C535823 and other concurrent tests use power_save=False throughout.
        logger().info("C1726589: power save skipped in concurrent STA+AP mode")
        ap_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
        logger().info(f"C1726589: DUT AP IP {ap_ip}, Pi will connect on wlan0 port {local_port}")
        ping_ok = False
        for attempt in range(3):
            try:
                if wifi_client.interfaces.wifi.ping(
                        server_ip=ap_ip, num_ping_attempts=ping_count) < 5:
                    ping_ok = True
                    break
            except Exception as exc:
                logger().info(f"C1726589: ping to {ap_ip} attempt {attempt + 1} failed: {exc}")
            time.sleep(2)
        assert ping_ok, f"Pi cannot reach DUT AP IP {ap_ip} on wlan0 before TCP connect"
        wlan_iface = wifi_client.interfaces.wifi.config.get("interface", "wlan0")
        remote_peer = remote_socket.interfaces.socket
        server_socket_id = lwip_socket_create(
            self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
        self._per_socket_close_sockopt(self.wifi_dut, server_socket_id)
        # Concurrent STA+AP: sync bind/listen/accept (asynch=1 accept hangs — see C535823 pattern).
        lwip_bind(
            self.wifi_dut, socket_fd=server_socket_id, ip_address=ap_ip, port=local_port)
        lwip_listen(self.wifi_dut, socket_fd=server_socket_id, backlog=0)
        time.sleep(5)
        since_time = time.perf_counter_ns()
        self.wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        self._accept_server_with_remote_client(
            server_socket_id, remote_peer, ap_ip, local_port, wlan_interface=wlan_iface,
            parallel_timeout=60, sync_accept=True)
        assert remote_peer.sock is not None, (
            f"Remote peer failed to connect to DUT AP at {ap_ip}:{local_port}")
        client_socket_id = server_socket_id + 1
        tx_buffer = "X" * pkt_length
        remote_peer.send_data_tcp(tx_buffer, use_server_socket=False)
        time.sleep(1)
        self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(
            socket_fd=client_socket_id, timeout=120, async_timeout=120)
        if remote_peer.sock is not None:
            try:
                remote_peer.sock.shutdown(socket.SHUT_RDWR)
                remote_peer.sock.close()
            except Exception:
                pass
            remote_peer.sock = None
        self._verify_remote_terminate(since_time=since_time)
        lwip_close(self.wifi_dut, socket_fd=client_socket_id)
        lwip_close(self.wifi_dut, socket_fd=server_socket_id)
        try:
            remote_socket.interfaces.socket.stop()
        except Exception:
            pass
        remote_peer.interface = wlan_iface
        remote_peer.start_server(port=local_port)
        server_ip = remote_peer.hostname_or_ip_address()
        if not server_ip:
            server_ip = wifi_client.interfaces.wifi.get_ip_address()
        server_port = remote_peer.server_port or local_port
        logger().info(
            f"C1726589 phase-2: DUT STA client TX to Pi server {server_ip}:{server_port}")
        self.wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        client_sock = lwip_socket_create(
            self.wifi_dut, domain="AF_INET", sock_type="SOCK_STREAM", protocol="IPPROTO_TCP")
        self._per_socket_close_sockopt(self.wifi_dut, client_sock)
        lwip_bind(
            self.wifi_dut, socket_fd=client_sock, ip_address=sta_ip, port=local_port)
        lwip_tcp_connect_with_retry(self.wifi_dut, client_sock, server_ip, server_port)
        logger().info("C1726589 phase-2: DUT STA connected to Pi TCP server")
        since_time = time.perf_counter_ns()
        tx_thread = Thread(
            target=lwip_send_data_pkts,
            args=(self.wifi_dut, client_sock, pkt_length, no_of_pkts, 1, server_ip, server_port),
            daemon=True,
        )
        tx_thread.start()
        time.sleep(2)
        remote_peer.stop()
        tx_thread.join(timeout=120)
        self._verify_remote_terminate(since_time=since_time, expected_port=server_port)
        lwip_close(self.wifi_dut, socket_fd=client_sock)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLAN | Siwx3xxCoexMode.BLE,
        "features": Siwx3xxFeatureBitMap.WPSSupportDisabled | Siwx3xxFeatureBitMap.PSKSecurity
                    | Siwx3xxFeatureBitMap.Aggregation | Siwx3xxFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Siwx3xxCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.FeatureLowPower |
                               Siwx3xxExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Siwx3xxExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Siwx3xxExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.WaitForSocketClose | Siwx3xxExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp | Siwx3xxConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19348')
def test_wifi_siwx3xx_udp_open_send_data_close_socket_c19348(
        sniffer_filter, wifi_access_point, wifi_dut, siwx3xx_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client):
    """This test case Verifies the udp client socket is open, send data,close functionality"""
    try:

        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     siwx3xx_collections=siwx3xx_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     remote_socket_factory=remote_socket_factory, wifi_client=wifi_client)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        wifi_thread.udp_single_socket_dut_client()

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, test_case=19348,
                                                        dut_mac_address=dut_mac_address, ap_mac_address=ap_mac_address,
                                                        siwx3xx_collections=siwx3xx_collections,
                                                        power_save=wifi_thread.power_save)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_verification.verify_sniffer_validation()

    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLAN | Siwx3xxCoexMode.BLE,
        "features": Siwx3xxFeatureBitMap.Default,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Siwx3xxCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default | Siwx3xxExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.WaitForSocketClose | Siwx3xxExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp | Siwx3xxConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C19349')
def test_wifi_siwx3xx_tcp_socket_dut_client_c19349(
        sniffer_filter, wifi_access_point, wifi_dut, siwx3xx_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client):
    """Verify 10 sockets functionality open 10 tcp client sockets and connect to server sockets and send data"""

    wifi_thread = None
    sockets_created = []

    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     siwx3xx_collections=siwx3xx_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     remote_socket_factory=remote_socket_factory, wifi_client=wifi_client)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        # ========================================================================
        # PERFORM DATA TRANSFER ON ALL SOCKETS
        # ========================================================================
        logger().info("=" * 80)
        logger().info("STARTING TCP DATA TRANSFER TEST")
        logger().info("=" * 80)

        wifi_thread.tcp_multiple_socket_dut_client()

        logger().info("=" * 80)
        logger().info("TCP DATA TRANSFER TEST COMPLETED SUCCESSFULLY")
        logger().info("=" * 80)

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, test_case=19349,
                                                        dut_mac_address=dut_mac_address, ap_mac_address=ap_mac_address,
                                                        siwx3xx_collections=siwx3xx_collections,
                                                        power_save=wifi_thread.power_save)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_verification.verify_sniffer_validation()

    except Exception as e:
        logger().error(f"Test failed with exception: {e}")
        logger().error(f"Exception type: {type(e).__name__}")
        import traceback
        logger().error(f"Traceback:\n{traceback.format_exc()}")
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        # Ensure sockets are closed in cleanup
        logger().info("=" * 80)
        logger().info("TEST CLEANUP - Ensuring all sockets are closed")
        logger().info("=" * 80)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLAN | Siwx3xxCoexMode.BLE,
        "features": Siwx3xxFeatureBitMap.Default,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Siwx3xxCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default | Siwx3xxExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.WaitForSocketClose | Siwx3xxExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp | Siwx3xxConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19350')
def test_wifi_siwx3xx_udp_socket_dut_client_c19350(
        wifi_access_point, wifi_dut, wifi_sniffer, siwx3xx_collections, request, sniffer_filter,
        remote_socket_factory, wifi_client):
    """Verify 10 sockets functionality open 10 UDP client sockets and connect to server sockets"""
    try:

        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     siwx3xx_collections=siwx3xx_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     remote_socket_factory=remote_socket_factory, wifi_client=wifi_client)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        wifi_thread.udp_multiple_socket_dut_client()

        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, test_case=19350,
                                                        dut_mac_address=dut_mac_address, ap_mac_address=ap_mac_address,
                                                        siwx3xx_collections=siwx3xx_collections,
                                                        power_save=wifi_thread.power_save)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_verification.verify_sniffer_validation()

    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLAN | Siwx3xxCoexMode.BLE,
        "features": Siwx3xxFeatureBitMap.Default | Siwx3xxFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Siwx3xxCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default | Siwx3xxExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.WaitForSocketClose | Siwx3xxExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp | Siwx3xxConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.config("net_perf_client",
                    net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C19357')
def test_wifi_siwx3xx_tcp_TX_with_message_size_greater_size_than_tcp_window_size_c19357(wifi_access_point, wifi_dut,
                                                                                    siwx3xx_collections, wifi_sniffer,
                                                                                    sniffer_filter, protocol,
                                                                                    net_perf_client,
                                                                                    wifi_client):
    """
        Verify TCP data transmission when the message size is greater than the TCP window size.

        This test case performs the following steps:
        1. Configures the WiFi sniffer to capture packets on the specified channel.
        2. Starts the WiFi sniffer to capture packets.
        3. Initializes and starts a WiFi join thread to connect the DUT to the access point.
        4. Retrieves the device IP and MAC address of the DUT and the BSSID of the access point.
        5. Initializes and starts a net performance client in server mode with a specified MSS value.
        6. Creates a TCP socket on the DUT and binds it to the device IP and server port.
        7. Sets the socket option for MSS on the DUT.
        8. Connects the DUT socket to the server.
        9. Sends multiple packets from the DUT to the server.
        10. Processes the output from the net performance client to verify throughput.
        11. Closes the socket on the DUT.
        12. Stops the WiFi sniffer and validates the captured packets for the configured MSS value.

        Args:
            wifi_access_point: The WiFi access point object.
            wifi_dut: The WiFi device under test (DUT) object.
            siwx3xx_collections: The SL collections object for handling exceptions.
            wifi_sniffer: The WiFi sniffer object for capturing packets.
            sniffer_filter: The filter to apply on the sniffer.
            protocol: The protocol to use for the net performance client (e.g., TCP).
            net_perf_client: The net performance client object.
            wifi_client: The WiFi client object.

        Raises:
            Exception: If any step in the test case fails.
        """
    sock = None
    try:
        tcp_window_size = 1000
        tcp_message_size = 1460
        capture_filename = "test_wifi_siwx3xx_tcp_TX_with_message_size_greater_size_than_tcp_window_size_c19357"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     siwx3xx_collections=siwx3xx_collections, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        device_ip, dut_mac_address = wifi_thread.dut_addr['device_ip'], wifi_thread.dut_addr['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        host_ip = wifi_thread.peer_server_ip()
        logger().info(f"Remote device ip :{host_ip}")
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                        mss_value=tcp_window_size, time_out=500)
        net_perf_client.interfaces.net_perf.start()
        server_port = net_perf_client.interfaces.net_perf.server_port
        sock = lwip_socket_create(wifi_dut)
        lwip_bind(wifi_dut, socket_fd=sock, ip_address=device_ip, port=server_port)
        wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(sock, option_name=Siwx3xxCustomSyncSockOptParms.SL_SI91X_SO_MSS,
                                                      cert_index=tcp_window_size)
        lwip_connect(wifi_dut, socket_fd=sock, ip_address=host_ip, port=server_port)

        tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=tcp_message_size))
        logger().info(f"*********** Sending packet with size --> {len(tx_buffer)} bytes ***********")
        try:
            data = lwip_send(wifi_dut, socket_fd=sock, data=tx_buffer, higher_data_len=1)
            status = SLStatus.SL_STATUS_OK
        except Exception as send_err:
            data = str(send_err)
            status = SLStatus.SL_STATUS_FAIL
            logger().info(f"lwip.send failed as expected for oversized TCP payload: {send_err}")
        error_code_pattern = r"errno:\s+(\d+)"
        match = re.search(error_code_pattern, str(data))
        error_code = 0
        if match:
            error_code = match.group(1)
            logger().info(f"\n Encountered Error Code: {error_code}\n")
        assert int(error_code) == 40, f"\n The Expected Error Code is 40, got {int(error_code)} \n"
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        lwip_close(wifi_dut, socket_fd=sock)
        logger().info(f"Successfully closed socket_id '{sock}' in the DUT")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        siwx3xx_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        logger().info("********** Validating MSS value in sniffer packets **********")
        packet_filter = f"(wlan.addr == {dut_mac_address}) && (tcp.options.mss_val == {tcp_window_size})"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)[
            'packet_count'], "Unable to find configured MSS value in sniffer packets"
    except Exception as e:
        if sock is not None:
            try:
                lwip_close(wifi_dut, socket_fd=sock)
            except Exception:
                pass
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        net_perf_client.interfaces.net_perf.close_files()
        net_perf_client.interfaces.net_perf.iperf_process.stop(10)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Siwx3xxCoexMode.WLAN | Siwx3xxCoexMode.BLE,
        "features": Siwx3xxFeatureBitMap.Default,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Siwx3xxCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default | Siwx3xxExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.WaitForSocketClose | Siwx3xxExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp | Siwx3xxConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init_client'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA', "cipher": "TKIP", "passphrase": '123456789',
                                               "standard": '11bg'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19365')
def test_wifi_siwx3xx_tcp_udp_data_tx_WPA_TKIP_c19365(
        wifi_sniffer, wifi_dut, wifi_access_point, request, siwx3xx_collections, sniffer_filter, remote_socket_factory,
        wifi_client):
    """Verify TCP ,UDP data reception of STAUT in WPA-TKIP mode"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     siwx3xx_collections=siwx3xx_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, remote_socket_factory=remote_socket_factory)
        wifi_thread.enc = "tkip"
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        wifi_thread.tcp_single_socket_dut_client()

        time.sleep(5)

        """ ******************* Creating UDP Socket *******************"""

        wifi_thread.udp_single_socket_dut_client()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Skipping PS POLL sniffer check; power save is disabled for this suite")

    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
