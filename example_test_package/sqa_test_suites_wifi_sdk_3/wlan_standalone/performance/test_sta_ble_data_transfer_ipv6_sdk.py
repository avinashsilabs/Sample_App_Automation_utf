import time
import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xJoinFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLEFeatureBitMap, Si91xBLECustomFeatureBitMap
from utf.utf_config import UtfConfig
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger
import ipaddress
import random
from random import randint


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9117
        1. Configuration of DUT in 2G : B/G/N/AX
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Enable the power save mode in DUT & BLE
        6. Stop the sniffer  
        7. Analyizing all sniffer capture packets for wpa3 functionality
    setup requirement:
        1. DUT(RS9117)
        2. WSDK 3.0 Board
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer K
"""


def random_ipv6_addr(network):
    """
    Generate a random IPv6 address in the given network
    Example: random_ipv6_addr("fd66:6cbb:8c10::/48")
    Returns an IPv6Address object.
    """
    net = ipaddress.IPv6Network(network)
    # Which of the network.num_addresses we want to select?
    addr_no = random.randint(0, net.num_addresses)
    # Create the random address by converting to a 128-bit integer, adding addr_no and converting back
    network_int = int.from_bytes(net.network_address.packed, byteorder="big")
    addr_int = network_int + addr_no
    addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
    return addr


class WLanThread(ThreadBase):
    client_info = {"mac_address": None, "ip_address": None}
    dut_info = {"mac_address": None, "ip_address": None}

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None, ssl_server=None,
                 wifi_client=None, test_id=None, ble_data_transfer=None, ping_from="remote", ping_count=10,
                 addr_type="global", traffic_type=None, protocol=None, net_perf_client=None, timeout=60,
                 data_transfer=None, test_case_no=None, ble_client=None, iperf_traffic=None, ble_client_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.ping_from = ping_from
        self.ping_count = ping_count
        self.ble_data_transfer = ble_data_transfer
        self.dut_add_dict = None
        self.addr_type = addr_type
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.data_transfer = data_transfer
        self.ssl_server = ssl_server
        self.ble_client = ble_client
        self.remote_ip = None
        self.test_case_no = test_case_no
        self.iperf_traffic = iperf_traffic
        self.ble_client_address = ble_client_address

    def ping_async(self):
        time.sleep(10)
        logger().info(f"Ping from DUT to remote")
        self.wifi_dut.interfaces.wifi.ping(server_ip=self.remote_ip, num_ping_attempts=self.ping_count,
                                           ping_timeout=10, ip_version='ipv6', ping_size=64)

        logger().info(f"Ping successful")

    def run(self):
        if self.test_case_no == 119377:
            protocol = 'TCP'
            traffic_type = 'TX'
        if self.test_case_no == 119376:
            protocol = 'TCP'
            traffic_type = 'RX'
        if self.test_case_no == 119380:
            protocol = 'UDP'
            traffic_type = 'TX'
        if self.test_case_no == 119379:
            protocol = 'UDP'
            traffic_type = 'RX'

        if self.ble_data_transfer:
            logger().info(f"BLE Data Transfer going to start")
            service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
            char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

            logger().info("================== Start BLE in DUT ====================")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address, "failed to initialize ble in dut"
            self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
            self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F)

            logger().info("=============== Start BLE ADV in DUT ====================")
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            logger().info("============== start scanning in remote ble device ======================")
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert self.ble_client_address, "failed to start scan in remote device"

            device_found = False
            sw = Stopwatch()
            while sw.elapsed_sec < 30:
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                if bt_dut_address in found_devices and \
                        found_devices[bt_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data:
                    device_found = True
                    break

            self.ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "no device found"

            logger().info("============== connect to ble dut =========================")
            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
            time.sleep(10)

            logger().info("======= get connection state")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"

            servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            assert len(servs) > 0, "no services fetched"
            assert len(chars) > 0, "fetched characters are empty"

            char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid,
                char_uid=char_uid)
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"

            self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            # subscribe to notifications
            self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                         char_uid=char_uid)

        self.dut_add_dict = self.sl_collections. \
            join_to_wifi_network(wifi_dut=self.wifi_dut,
                                 wifi_access_point=self.wifi_access_point,
                                 associated=self.wifi_dut.interfaces.wifi.associated,
                                 ip_version='ipv6',
                                 ping_after_power_save=False,
                                 ping_before_power_save=False,
                                 power_save=False,
                                 ipv6_type=self.addr_type,
                                 retry_count=3
                                 )
        logger().info(
            f"DUT MAC ADDRESS :  {self.dut_add_dict['dut_mac_address']} "
            f"DUT IPV6 ADDRESS : {self.dut_add_dict['device_ip']}")

        self.wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)
        self.remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.addr_type)
        self.remote_ip = ipaddress.ip_address(self.remote_ip)
        logger().info(f"Remote device ip:{self.remote_ip}")
        if self.test_case_no == 119376:
            self.wifi_dut.interfaces.wifi.set_socket_config()

        if self.test_case_no == 119377 or self.test_case_no == 119376 or self.test_case_no == 119380 or \
                self.test_case_no == 119379:
            logger().info(f"BLE Data Transfer is going to start")
            ble_data = ble_notify(self.wifi_dut, self.ble_client_address)
            ble_data.start()

        if self.iperf_traffic:
            self.sl_collections.run_traffic(
                wifi_dut=self.wifi_dut,
                net_perf_client=self.net_perf_client,
                protocol=protocol,
                device_ip=self.dut_add_dict['device_ip'],
                host_ip=self.remote_ip,
                timeout=30,
                traffic_type=traffic_type,
                ip_version=6,
                buffer_size_tcp=1380,
                buffer_size_udp=1390,
                async_socket=1
            )
        if self.data_transfer:
            if self.traffic_type == "TX":
                buffer_length = 1100
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                self.ssl_server.interfaces.ssl.start_server(ip_version=6)
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                # Open ssl client socket in the DUT
                sock = self.wifi_dut.interfaces.wifi.socket(domain='AF_INET6')
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")#, option_val="tls_1_2"
                local_port = randint(5001, 60000)
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=self.remote_ip,
                                                          server_port=port1, ip_len=16, timeout=15)
                pkt_count = 50000
                time.sleep(2)
                server_socket_no = 1
                if self.ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                    self.ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
                result = self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
                time.sleep(5)
                logger().info(f"Number of bytes sent by dut {result}")
                bytes_sent = result
                bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
                logger().info(
                    f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                logger().info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()
                time.sleep(5)
            if self.traffic_type == "RX":
                buffer_length = 1370
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                time.sleep(5)
                self.wifi_dut.interfaces.wifi.set_socket_config()
                # Open ssl client socket in the DUT
                time.sleep(2)
                sock = self.wifi_dut.interfaces.wifi.async_sdk_socket(domain='AF_INET6', stream_type="SOCK_STREAM",
                                                                 protocol="IPPROTO_TCP")
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
                local_port = randint(5001, 60000)
                self.ssl_server.interfaces.ssl.start_server(ip_version=6)
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                time.sleep(3)
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                          server_port=port1, ip_len=16, timeout=15)
                socket_no = 1
                pkt_count = 50000
                duration = 60
                self.ssl_server.interfaces.ssl.send_data(socket_no, pkt_count, msg_length=buffer_length, duration=duration)
                time.sleep(80)
                bytes_sent = self.ssl_server.interfaces.ssl.data_send_stats(socket_no)
                result = self.wifi_dut.interfaces.wifi.get_socket_rx_stats(sock, no_of_pkts="pkt_count", ttl=30)
                logger().info(f"*** result of rx_stats in wifidut {result}")
                bytes_received = int(result)
                logger().info(f"bytes sent by remote peer -> {bytes_sent}")
                logger().info(f"bytes received on socket {sock} -> {bytes_received}")
                logger().info(f"SSL rx throughput ->  {((bytes_received * 8) / (1000 * 1000 * duration))} Mbps")
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                logger().info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()
                time.sleep(5)

        if self.ble_data_transfer:
            data = "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdata"
            logger().info(f"unsubcribing the ble notifications")
            self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
            time.sleep(1)

            logger().info("====================== Validate Data ===========================")
            notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
            logger().info(f' *********************** Notification is {notifications} ***********************')
            assert len(notifications) > 0, "received data is empty"
            assert notifications[0] == data, "failed to fetch data"

            logger().info("******************** ble_remove_service ***********************")
            self.wifi_dut.interfaces.wifi.ble_remove_service()

            logger().info("================== Disconnecting from DUT ========================")
            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
            self.ble_client.interfaces.bluetooth.close()


class ble_notify(WLanThread):
    def __init__(self, wifi_dut, ble_client_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client_address = ble_client_address

    def run(self):
        data = "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdata"
        sw = Stopwatch()
        while sw.elapsed_sec < 35:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data, ble_remote_dev_address=self.ble_client_address)
            time.sleep(0.5)


@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default  # Default BLE features
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,  # Enable asynchronous GATT operations
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default  # Default BLE custom features
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST  # Indication confirmation from host
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST, # MTU exchange from host
        "thread_config": {
                        "wifi": {"count": 1, "stack_len": 3072, "priority": 8},
                        "ble": {"count": 1, "stack_len": 2048, "priority": 8}, }
    }
)
@pytest.mark.test_src_map_id('C401901')
def test_BLE_WLAN_IPV6_TCP_TX_C401901(
        firmware_loader,
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        net_perf_client,
        protocol,
):
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_client=wifi_client, test_name=test_name, ble_client=ble_client,
                              sl_collections=sl_collections, ping_count=ping_count, protocol=protocol,
                              wifi_access_point=wifi_access_point, net_perf_client=net_perf_client, iperf_traffic=True,
                              test_case_no=119377, ble_data_transfer=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default  # Default BLE features
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,  # Enable asynchronous GATT operations
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default  # Default BLE custom features
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST  # Indication confirmation from host
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "thread_config": {
                        "wifi": {"count": 1, "stack_len": 3072, "priority": 8},
                        "ble": {"count": 1, "stack_len": 2048, "priority": 8}, }

    }
)
@pytest.mark.test_src_map_id('C401902')
def test_BLE_WLAN_IPV6_TCP_RX_C401902(
        firmware_loader,
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        net_perf_client,
        protocol,
):
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, iperf_traffic=True,
                              test_name=test_name, sl_collections=sl_collections, net_perf_client=net_perf_client,
                              ping_count=ping_count, wifi_client=wifi_client, protocol=protocol, test_case_no=119376,
                              ble_client=ble_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default  # Default BLE features
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,  # Enable asynchronous GATT operations
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default  # Default BLE custom features
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST  # Indication confirmation from host
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST, # MTU exchange from host
        "thread_config": {
                        "wifi": {"count": 1, "stack_len": 3072, "priority": 8},
                        "ble": {"count": 1, "stack_len": 2048, "priority": 8}, }
    }
)
@pytest.mark.test_src_map_id('C401903')
def test_BLE_WLAN_IPV6_UDP_TX_C401903(
        firmware_loader,
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        net_perf_client,
        protocol,
):
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_client=wifi_client, test_name=test_name, ble_client=ble_client,
                              sl_collections=sl_collections, ping_count=ping_count, protocol=protocol,
                              wifi_access_point=wifi_access_point, net_perf_client=net_perf_client, iperf_traffic=True,
                              test_case_no=119380, ble_data_transfer=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default  # Default BLE features
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,  # Enable asynchronous GATT operations
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default  # Default BLE custom features
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST  # Indication confirmation from host
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "thread_config": {
                        "wifi": {"count": 1, "stack_len": 3072, "priority": 8},
                        "ble": {"count": 1, "stack_len": 2048, "priority": 8}, }

    }
)
@pytest.mark.test_src_map_id('C401904')
def test_BLE_WLAN_IPV6_UDP_RX_C401904(
        firmware_loader,
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        net_perf_client,
        protocol,
):
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, iperf_traffic=True,
                              test_name=test_name, sl_collections=sl_collections, net_perf_client=net_perf_client,
                              ping_count=ping_count, wifi_client=wifi_client, protocol=protocol, test_case_no=119379,
                              ble_client=ble_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.IPv6Mode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default  # Default BLE features
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,  # Enable asynchronous GATT operations
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default  # Default BLE custom features
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST  # Indication confirmation from host
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST, # MTU exchange from host
        "thread_config": {
                        "wifi": {"count": 1, "stack_len": 3072, "priority": 8},
                        "ble": {"count": 1, "stack_len": 2048, "priority": 8}, },
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.test_src_map_id('C401905')
def test_BLE_WLAN_IPV6_SSL_TX_C401905(
        firmware_loader,
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        net_perf_client,
        protocol,
        ssl_server
):
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_client=wifi_client, test_name=test_name, ble_client=ble_client,
                              sl_collections=sl_collections, ping_count=ping_count, protocol=protocol,
                              wifi_access_point=wifi_access_point, net_perf_client=net_perf_client, data_transfer=True,
                              test_case_no=119380, ble_data_transfer=True, traffic_type='TX', ssl_server=ssl_server)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.IPv6Mode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default  # Default BLE features
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,  # Enable asynchronous GATT operations
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default  # Default BLE custom features
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST  # Indication confirmation from host
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "thread_config": {
                        "wifi": {"count": 1, "stack_len": 3072, "priority": 8},
                        "ble": {"count": 1, "stack_len": 2048, "priority": 8}, },
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]

    }
)
@pytest.mark.test_src_map_id('C401906')
def test_BLE_WLAN_IPV6_SSL_RX_C401906(
        firmware_loader,
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        net_perf_client,
        protocol,
        ssl_server
):
    try:

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, data_transfer=True,
                              test_name=test_name, sl_collections=sl_collections, net_perf_client=net_perf_client,
                              ping_count=ping_count, wifi_client=wifi_client, protocol=protocol, test_case_no=119379,
                              ble_client=ble_client, traffic_type='RX', ssl_server=ssl_server, ble_data_transfer=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)