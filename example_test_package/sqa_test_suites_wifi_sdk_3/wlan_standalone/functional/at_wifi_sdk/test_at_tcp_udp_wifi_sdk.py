import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    SlNetRegionCode,
    SocketOptionLevel,
    SocketOptionName,
    SocketProtocol,
    SocketType,
    SocketDomain,
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xPowerSaveModes,
    DeviceConstants,
    Si91xPowerSaveProcedureTypes,
    Si91xCustomFeatureBitMap,
    SocketOptions,
    Si91xOperatingMode,
    Si91xCustomSyncSockOptParms,
    Si91xJoinFeatureBitMap,
    SlNetProfileId,
)
from threading import Thread
import threading
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from random import randint
import random
import string
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.bsd_errors import BSDErrnoStatus

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

    Author: Sakshi Agrawal
"""

def logger():
    return get_logger(__name__)


class SnifferValidationProcess:

    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None, ap_mac_address=None,
                 sniffer_filter=None, sl_collections=None, test_case=None):
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.sl_collections = sl_collections
        self.test_case = test_case

    def verify_sniffer_validation(self):

        if self.test_case == 778694 or self.test_case == 778695:
            filters_name = None
            device_address = {'sa_addr': self.dut_mac_address, 'da_addr': self.ap_mac_address,
                              'ta_addr': self.dut_mac_address, 'ra_addr': self.ap_mac_address}

            if self.test_case == 778694:
                filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'ps_poll',
                                4: 'dhcp_4_way_handshake_packets', 5: 'tcp_syn_with_syn_ack_with_ack'}

            if self.test_case == 778695:
                filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'ps_poll',
                                4: 'dhcp_4_way_handshake_packets'}

            output = self.sl_collections.sniffer_validation_for_packet_filters(
                self.wifi_sniffer, self.sniffer_filter, device_address, filters_name=filters_name)

            logger().info(f'\n OUTPUT 1 = {output}\n')
            assert all(output.values()), 'Unable to find expected filter'


class WifiJoin():
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, sniffer_filter=None, wifi_sniffer=None,
                 sl_collections=None, test_name=None, remote_socket_factory=None, ap_mac_address=None, test_case=None,
                 remote_socket=None):
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.test_case = test_case
        self.dut_addr = None
        self.device_ip = None
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.enc = "ccmp"
        self.remote_socket_factory = remote_socket_factory
        self.remote_socket = remote_socket
        self.dut_mac_addr = None

    def join_ap(self):
        device_ip = self.sl_collections.join_to_wifi_network_at_cmd(self.wifi_dut, self.wifi_access_point, security=self.wifi_access_point.interfaces.wifi.security,)

    def transmit_tcp_data(self, sock_id, client_socket, no_of_pkts: int =50, data_length: int = 20):
        if self.test_case == 778699:
            data_length = 1400
            no_of_pkts = 100
        if self.test_case == 778694:
            data_length = 20
            no_of_pkts = 1000
        count = 0
        logger().info(f"\n==================== Starting the TCP TX data Transfer ====================\n")
        while count < no_of_pkts:
            count += 1
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=data_length)
            )
            try:
                logger().info(f"\n###################### Sending TCP Data Packet: {count} ######################\n")
                self.wifi_dut.interfaces.wifi.socket_send(
                    socket_id=sock_id,
                    data_length=data_length,
                    data=sent_data
                )
                client_socket.set_recv_timeout(socket_type=0)
                received_data = client_socket.recv_data_tcp(data_length)
                logger().info(
                    f"\n###################### Received TCP Data: {received_data} ######################\n"
                )
                assert (
                    sent_data == received_data
                ), f"Data mismatch in sent and received data"
            except Exception as e:
                logger().info(
                    f"\n Socket Data Transfer Failed in {count} number of packets\n"
                )
                raise e

    def transmit_udp_data(self, sock_id, client_socket, server_ip, local_port, no_of_pkts: int = 50, data_length: int = 20):
        if self.test_case == 778695:
            data_length = 20
            no_of_pkts = 1000
        count = 0
        logger().info(f"\n ====================Starting the UDP TX data Transfer==================== \n")
        while count < no_of_pkts:
            count += 1
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=data_length)
            )
            try:
                logger().info(f"\n###################### Sending TCP Data Packet: {count} ######################\n")
                self.wifi_dut.interfaces.wifi.socket_send(
                    socket_id=sock_id,
                    data_length=data_length,
                    data=sent_data,
                    remote_ip_address=server_ip,
                    remote_port=local_port
                )
                client_socket.set_recv_timeout(socket_type=1, use_client_socket=True)
                received_data = client_socket.recv_data_udp(data_length)[0]
                logger().info(
                    f"\n###################### Received UDP Data: {received_data} ######################\n"
                )
                assert (
                    sent_data == received_data
                ), f"Data mismatch in sent and received data"
            except Exception as e:
                logger().info(
                    f"\n Socket Data Transfer Failed in {count} number of packets\n"
                )
                raise e


    def tcp_single_socket_dut_client(self, data_transfer=True):
        local_port = 5001
        keep_alive = 60
        try:
            # Step 1: Create a socket on the DUT
            logger().info(f"\n ====================Creating a TCP Socket on the DUT==================== \n")
            sock_id = int(self.wifi_dut.interfaces.wifi.create_socket())

            logger().info(f"\n====================Setting the socket option SO_KEEPALIVE with {keep_alive} seconds ====================\n")
            # Step 2: Set socket options
            self.wifi_dut.interfaces.wifi.setSockopt(
                socket_id=sock_id,
                option_level=SocketOptionLevel.SOL_SOCKET,
                option=SocketOptionName.SO_KEEPALIVE,
                option_values=(keep_alive,)
            )

            logger().info(f"\n====================Starting the TCP Server Socket on the remote socket factory==================== \n")
            # Step 3: Start a server socket on the remote socket factory
            client_socket = self.remote_socket_factory.interfaces.socket.create_socket()
            client_socket.start_server(port=local_port)

            # Step 4: Get the server IP and connect the DUT socket to the server socket
            server_ip = self.wifi_client.interfaces.wifi.get_ip_address()

            logger().info(f"\n====================Connecting the DUT socket to the server socket at {server_ip}:{local_port}==================== \n")
            for count in range(3):
                connect_status = False
                try:
                    self.wifi_dut.interfaces.wifi.socket_connect(socket_id=sock_id, address=server_ip, port=local_port)
                    connect_status = True
                    break
                except:
                    logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                    assert connect_status, "Socket connection failed in DUT"
            logger().info("*********** Socket connection is successful ************")

            #  Send data from the DUT socket to the server socket
            if data_transfer:
                self.transmit_tcp_data(sock_id, client_socket)

            if self.test_case == 778699:
                logger().info(f"\n Wait For KEEPALIVE * 11 = {keep_alive} * 11 seconds to Verify the SO_KEEPALIVE functionality  \n")
                time.sleep(keep_alive*11)

            logger().info(f"\n====================Closing the socket with sock id {sock_id} ====================\n")
            # Step 6: Close the DUT socket
            self.wifi_dut.interfaces.wifi.close_socket(socket_id=sock_id)

        except Exception as e:

            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)



    def udp_single_socket_dut_client(self):
        local_port = 8001
        try:

            # Step 1: Create a socket on the DUT
            logger().info(f"\n ====================Creating a TCP Socket on the DUT==================== \n")
            sock_id = int(self.wifi_dut.interfaces.wifi.create_socket(type=SocketType.SOCK_DGRAM, protocol=SocketProtocol.IPPROTO_UDP))

            # Step 3: Start a server socket on the remote socket factory
            logger().info(f"\n====================Starting the UDP Server Socket on the remote socket factory==================== \n")
            client_socket = self.remote_socket_factory.interfaces.socket.create_socket()
            client_socket.start_server(port=local_port, socket_type=1)

            # Step 4: Get the server IP and connect the DUT socket to the server socket
            server_ip = self.wifi_client.interfaces.wifi.get_ip_address()


            #  Send data from the DUT socket to the server socket
            self.transmit_udp_data(sock_id, client_socket, server_ip, local_port)

            # Step 6: Close the DUT socket
            logger().info(f"\n====================Closing the socket with sock id {sock_id} ====================\n")
            self.wifi_dut.interfaces.wifi.close_socket(socket_id=sock_id)

        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)




@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=['close_sockets', 'deinit'])
@pytest.mark.config("wifi_dut",
                    wifi={
                        "oper_mode": Si91xOperatingMode.WiFiClient,
                    })
@pytest.mark.config("wifi_access_point",wifi={"security": 'Open', "passphrase": '123456789'})
def test_wifi_sdk_tcp_open_send_data_close_socket_c778694(
     wifi_access_point, wifi_dut, sl_collections,  request,
    remote_socket_factory, wifi_client, wifi_sniffer, sniffer_filter):
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_client=wifi_client,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_name=test_name,
            remote_socket_factory=remote_socket_factory,
            test_case=778694
        )

        obj.join_ap()
        obj.tcp_single_socket_dut_client()

        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_addr}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, test_case=778694,
                                                        dut_mac_address=dut_mac_addr, ap_mac_address=ap_mac_address,
                                                        sl_collections=sl_collections)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_verification.verify_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []



@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=['close_sockets', 'deinit'])
@pytest.mark.config("wifi_dut",
                    wifi={
                        "oper_mode": Si91xOperatingMode.WiFiClient,
                    })
@pytest.mark.config("wifi_access_point",wifi={"security": 'Open', "passphrase": '123456789'})
def test_wifi_sdk_udp_open_send_data_close_socket_c778695(
     wifi_access_point, wifi_dut, sl_collections,  request,
    remote_socket_factory, wifi_client, wifi_sniffer, sniffer_filter):
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_client=wifi_client,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_name=test_name,
            remote_socket_factory=remote_socket_factory,
            test_case=778695
        )

        obj.join_ap()
        obj.udp_single_socket_dut_client()

        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_addr}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, test_case=778695,
                                                        dut_mac_address=dut_mac_addr, ap_mac_address=ap_mac_address,
                                                        sl_collections=sl_collections)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_verification.verify_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []

@pytest.mark.skip("At commands does not support 1400 bytes data transfer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=['close_sockets', 'deinit'])
@pytest.mark.config("wifi_dut",
                    wifi={
                        "oper_mode": Si91xOperatingMode.WiFiClient,
                    })
@pytest.mark.config("wifi_access_point",wifi={ "security": 'Open', "passphrase": '123456789'})
def test_wifi_sdk_tcp_TX_send_100_1400_bytes_c778699(
     wifi_access_point, wifi_dut, sl_collections,  request,
    remote_socket_factory, wifi_client, wifi_sniffer, sniffer_filter):
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_client=wifi_client,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_name=test_name,
            remote_socket_factory=remote_socket_factory,
            test_case=778699
        )

        obj.join_ap()
        obj.tcp_single_socket_dut_client()

        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_addr}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, test_case=778694,
                                                        dut_mac_address=dut_mac_addr, ap_mac_address=ap_mac_address,
                                                        sl_collections=sl_collections)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_verification.verify_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=['close_sockets', 'deinit'])
@pytest.mark.config("wifi_dut",
                    wifi={
                        "oper_mode": Si91xOperatingMode.WiFiClient,
                    })
@pytest.mark.config("wifi_access_point",wifi={ "security": 'open', "passphrase": '123456789'})
def test_wifi_sdk_verify_so_keepalive_functionality_c778699(
     wifi_access_point, wifi_dut, sl_collections,  request,
     remote_socket_factory, wifi_client, wifi_sniffer, sniffer_filter):
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_client=wifi_client,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            sl_collections=sl_collections,
            test_name=test_name,
            remote_socket_factory=remote_socket_factory,
            test_case=778699
        )

        obj.join_ap()
        obj.tcp_single_socket_dut_client(data_transfer=False)

        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_addr}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, test_case=778694,
                                                        dut_mac_address=dut_mac_addr, ap_mac_address=ap_mac_address,
                                                        sl_collections=sl_collections)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_verification.verify_sniffer_validation()

        logger().info(f"Starting the Keep Alive Validation with duration = 60 seconds")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=dut_mac_addr,
            ra_addr=ap_mac_address, filter_name="keep_alive")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], f"Keep alive packets not found in sniffer packets"
        num = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'find_packet_num']
        logger().info(f"Keep Alive Packets Found in Sniffer: {num}")


    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []

