import time
import uuid
from datetime import datetime
from typing import Dict
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xCoexMode,
                                                   Si91xFeatureBitMap, Si91xConfigFeatureBitMap,
                                                   Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap)
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf_wiseconnect_3.tests.sl_status import SLStatus

"""The testcases added in this file run below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : BGN
        2. Association to Third party AP
        3. Get the ip address through DHCP
        4. Add multicast address to the multicast group
        5. Run Traffic
        6. Leave Multicast & verify the data integrity checks

    setup requirement:
        1. DUT(Si91x)
        2. NUC
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        
    Author : Saurabh Sharma
"""


def logger():
    return get_logger(__name__)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, net_perf_client=None, wifi_client=None,
                 protocol=None, capture_filename=None, sl_collections=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.capture_filename = capture_filename
        self.sl_collections = sl_collections
        self.dut_addr = None

    def run(self):
        try:
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)
            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")

    def get_igmp_list(self, dut_mac_address, decryption_key: str, print_layers: list, capture_filename) -> Dict[
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
        return igmp_capture_list


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
        }
    )
]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unsassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_multicast_receive_TC19369(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client, request,
                                        wifi_client, protocol, sl_collections, net_perf_client):
    try:
        capture_filename = request.node.name
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        timeout = 60
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address()

        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=multicast_ip, time_out=timeout,
                                                        protocol=protocol, time_to_leave="32", bandwidth="60M",
                                                        host_role="C")
        logger().info(f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}")
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** start listening  ******")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=wifi_obj.dut_addr['device_ip'], remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1470, ttl=30, throughput_type=4, qos=0, async_socket=1)

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        wifi_dut.interfaces.wifi.sl_net_leave_multicast_address()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        igmp_capture_list = wifi_obj.get_igmp_list(wifi_obj.dut_addr['dut_mac_address'], decryption_key, ["igmp"],
                                                   capture_filename)
        assert len(igmp_capture_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unsassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_multicast_group_leave_TC19370(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client, request,
                                                wifi_client, protocol, sl_collections, net_perf_client):
    try:
        capture_filename = request.node.name
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        timeout = 60
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, sl_collections=sl_collections)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
        for count in range(0, 2):
            if count % 2 == 0:
                logger().info(f"DUT joining to the multicast group {multicast_ip}")
                wifi_dut.interfaces.wifi.sl_net_join_multicast_address()
                sl_status = SLStatus.SL_STATUS_OK
            else:
                wifi_dut.interfaces.wifi.sl_net_leave_multicast_address()
                sl_status = SLStatus.SL_STATUS_TIMEOUT

            net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=multicast_ip, time_out=timeout,
                                                            protocol=protocol, time_to_leave="32", bandwidth="60M",
                                                            host_role="C")
            logger().info(f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}")
            logger().info(f"***** starting iperf ******")
            net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** start listening  ******")
            wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                           local_port=net_perf_client.interfaces.net_perf.client_port,
                                           local_ip=wifi_obj.dut_addr['device_ip'], remote_ip=host_ip,
                                           remote_port=net_perf_client.interfaces.net_perf.client_port,
                                           size=1470, ttl=30, throughput_type=4, qos=0, async_socket=1,
                                           expected_status=sl_status)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        igmp_list = wifi_obj.get_igmp_list(wifi_obj.dut_addr['dut_mac_address'], decryption_key, ['igmp'],
                                           capture_filename)
        assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
#                              "disassociated"])
# def test_wifi_sdk_multicast_filter_select_all_TC19372(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client,
#                                                       logger, sl_collections):
#     try:
#         capture_filename = "test_wifi_sdk_multicast_filter_select_all_TC19372"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
#         wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_SET_ALL, multicast_mac)
#
#         logger.info(f"DUT joining to the multicast group {multicast_ip}")
#         wifi_dut.interfaces.wifi.join_multicast_address(interface="client", multicast_address=multicast_ip)
#         socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
#         assert socket_id == 0, f"socket id received is wrong, expected is 0"
#         logger.info(f"socket id received is {socket_id} which is expected")
#         wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)
#
#         logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
#         multicast_client.interfaces.multicast.start_server()
#
#         logger.info(
#             f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
#         multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
#         multicast_client.interfaces.multicast.socket_close()
#         time.sleep(30)
#         logger.info(f"Closing socket_id->{socket_id}")
#         result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
#         assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{socket_id}"
#         logger.info(f"Successfully closed socket_id->{socket_id}")
#
#         result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)
#         bytes_received = int(result.split(b":")[1])
#         bytes_sent = (no_of_pkts * buffer_length)
#         packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)
#         logger.info(f"Packet loss {packet_loss}")
#         assert packet_loss < 20, "Packet loss is not in tolerance level"
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#         igmp_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ['igmp'],
#                                                          capture_filename, ap_bssid)
#         assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
#                              "disassociated"])
# def test_wifi_sdk_multicast_filter_clear_all_TC19373(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client,
#                                                      logger, sl_collections):
#     try:
#         capture_filename = "test_wifi_sdk_multicast_filter_clear_all_TC19373"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
#         wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_CLEAR_AL, multicast_mac)
#
#         logger.info(f"DUT joining to the multicast group {multicast_ip}")
#         wifi_dut.interfaces.wifi.join_multicast_address(interface="client", multicast_address=multicast_ip)
#         socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
#         assert socket_id == 0, f"socket id received is wrong, expected is 0"
#         logger.info(f"socket id received is {socket_id} which is expected")
#         wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)
#
#         logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
#         multicast_client.interfaces.multicast.start_server()
#
#         logger.info(
#             f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
#         multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
#         multicast_client.interfaces.multicast.socket_close()
#         time.sleep(30)
#         logger.info(f"Closing socket_id->{socket_id}")
#         result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
#         assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{socket_id}"
#         logger.info(f"Successfully closed socket_id->{socket_id}")
#
#         result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)
#         bytes_received = int(result.split(b":")[1])
#         assert bytes_received == 0, "Data received on multicast socket even though multicast_filter_clear_all is selected "
#         logger.info(
#             "Data is not received on multicast socket when multicast_filter_clear_all filter is selected which is "
#             "expected")
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#         igmp_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ['igmp'],
#                                                          capture_filename, ap_bssid)
#         assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
#                              "disassociated"])
# def test_wifi_sdk_multicast_filter_clear_specific_TC19374(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client,
#                                                           logger, sl_collections):
#     try:
#         capture_filename = "test_wifi_sdk_multicast_filter_clear_specific_TC19374"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
#         for count in range(0, 2):
#             if count == 1:
#                 wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_CLEAR_BIT, multicast_mac)
#             logger.info(f"DUT joining to the multicast group {multicast_ip}")
#             wifi_dut.interfaces.wifi.join_multicast_address(interface="client", multicast_address=multicast_ip)
#             socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
#             assert socket_id == 0, f"socket id received is wrong, expected is 0"
#             logger.info(f"socket id received is {socket_id} which is expected")
#             wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)
#
#             logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
#             multicast_client.interfaces.multicast.start_server()
#
#             logger.info(
#                 f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
#             multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
#             multicast_client.interfaces.multicast.socket_close()
#             time.sleep(30)
#             logger.info(f"Closing socket_id->{socket_id}")
#             result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
#             assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{socket_id}"
#             logger.info(f"Successfully closed socket_id->{socket_id}")
#
#             result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)
#             bytes_received = int(result.split(b":")[1])
#             bytes_sent = (no_of_pkts * buffer_length)
#             packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)
#             if count == 0:
#                 logger.info(f"Packet loss {packet_loss}")
#                 assert packet_loss < 20, "Packet loss is not in tolerance level"
#             else:
#                 assert bytes_received == 0, "Data received on multicast socket even though the multicast address is " \
#                                             "removed from the multicast group"
#             logger.info("Data is not received on multicast socket when the multicast address is removed from the "
#                         "multicast group which is expected")
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#         igmp_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ['igmp'],
#                                                          capture_filename, ap_bssid)
#         assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
#                              "disassociated"])
# def test_wifi_sdk_multicast_filter_add_specific_TC19375(wifi_sniffer, wifi_access_point, wifi_dut, multicast_client,
#                                                         logger, sl_collections):
#     try:
#         capture_filename = "test_wifi_sdk_multicast_filter_add_specific_TC19375"
#         channel = wifi_access_point.interfaces.wifi.channel
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         logger.info(f"Device mac address: {dut_mac_address}")
#
#         ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
#         for count in range(0, 2):
#             if count == 0:
#                 wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_CLEAR_AL, multicast_mac)
#             else:
#                 wifi_dut.interfaces.wifi.multicast_filter(MulticastParams.MULTICAST_MAC_ADD_BIT, multicast_mac)
#             logger.info(f"DUT joining to the multicast group {multicast_ip}")
#             wifi_dut.interfaces.wifi.join_multicast_address(interface="client", multicast_address=multicast_ip)
#             socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
#             assert socket_id == 0, f"socket id received is wrong, expected is 0"
#             logger.info(f"socket id received is {socket_id} which is expected")
#             wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)
#
#             logger.info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
#             multicast_client.interfaces.multicast.start_server()
#
#             logger.info(
#                 f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
#             multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
#             multicast_client.interfaces.multicast.socket_close()
#             time.sleep(30)
#
#             result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)
#             bytes_received = int(result.split(b":")[1])
#             bytes_sent = (no_of_pkts * buffer_length)
#             packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)
#
#             if count == 0:
#                 assert bytes_received == 0, "Data received on multicast socket even though multicast_filter_clear_all is " \
#                                             "selected "
#             else:
#                 logger.info(f"Packet loss {packet_loss}")
#                 assert packet_loss < 20, "Packet loss is not in tolerance level"
#
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#         decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#         igmp_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ['igmp'],
#                                                          capture_filename, ap_bssid)
#         assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
#         sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
