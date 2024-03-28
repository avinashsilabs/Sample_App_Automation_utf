from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xBTFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xJoinFeatureBitMap, Si91xCertificateType, \
    Si91xCertIdentifier
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.stopwatch import Stopwatch
import string
from random import choices
from utf.utils.iperf.iperf_utils import ping

"""This function runs below test steps for DUT-Si91x
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        6. Enable the power save mode in DUT
        7. Initiates ble in DUT
        8. run ble in slave / master mode
        9. Analyzing all sniffer capture packets
        
    setup requirement:
        1. soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: Saurabh Sharma

"""


def logger():
    return get_logger(__name__)


class WifiThreadFunctionality(ThreadBase):
    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, wifi_client=None, sl_collections=None,
                 sniffer_filter=None, test_case=None, net_perf_client=None, traffic=None, qos=None, protocol=None,
                 ssl_server=None, http_server=None, index_path=None, ping_count=None):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.device_ip = None
        self.dut_addr = None
        self.ap_mac_address = None
        self.host_ip = None
        self.iperf_throughput = None
        self.test_case = test_case
        self.net_perf_client = net_perf_client
        self.traffic = traffic
        self.qos = qos
        self.protocol = protocol
        self.ssl_server = ssl_server
        self.http_server = http_server
        self.index_path = index_path
        self.ping_count = ping_count

    def run(self):
        try:
            self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"******** HOST IP {self.host_ip} *******")
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"******** AP MAC ADDRESS {self.ap_mac_address} *******")
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)

            if self.test_case == "198667":
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol, tos_value=self.traffic)
                logger().info(
                    f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}, "
                    f"tos_value: {self.traffic}")
                logger().info(f"***** starting iperf ******")
                self.net_perf_client.interfaces.net_perf.start()
                logger().info(f"***** send traffic  ******")
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=self.host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    size=1460, ttl=30, throughput_type=1, qos=self.qos)
                logger().info("data transfer is successful")
                time.sleep(3)

            if self.test_case == "198668":
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol, tos_value=self.traffic,
                                                                     time_out=120)
                logger().info(
                    f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}, "
                    f"tos_value: {self.traffic}")
                logger().info(f"***** start iperf  ******")
                self.net_perf_client.interfaces.net_perf.start()
                logger().info(f"***** Start listening ******")
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=self.host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    size=1470, ttl=120, throughput_type=3, qos=self.qos,
                                                    timeout=150)
                logger().info("data transfer is successful")

            if self.test_case == "198678":
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol, tos_value=self.traffic,
                                                                     time_out=30)
                logger().info(
                    f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}, "
                    f"tos_value: {self.traffic}")
                logger().info(f"***** start iperf  ******")
                self.net_perf_client.interfaces.net_perf.start()
                logger().info(f"***** Start listening ******")
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=self.host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    size=1470, ttl=30, throughput_type=3, qos=self.qos,
                                                    timeout=45)
                logger().info("data transfer is successful")

            if self.test_case == "198670":
                logger().info(f"********** Calling IPERF RX UDP traffic DUT configured as Server **************")
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol, tos_value=self.traffic)
                logger().info(
                    f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}, "
                    f"tos_value: {self.traffic}")
                logger().info(f"***** starting iperf ******")
                self.net_perf_client.interfaces.net_perf.start()
                logger().info(f"***** Start listening  ******")
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                                    local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=self.host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    size=1470, ttl=30, throughput_type=4, qos=self.qos)
                logger().info("data transfer is successful")
                time.sleep(5)

            if self.test_case == 198671 or self.test_case == 198672:
                local_port = 5001

                """ ***** Open ssl server socket in remote device(Raspberry pi or static device) ***** """
                self.ssl_server.interfaces.ssl.start_server(port=local_port)
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                sock = self.wifi_dut.interfaces.wifi.socket()
                logger().info(f" ******************* Sock ID {sock} ******************** ")

                """ ***** Enable ssl option for socket opened ***** """
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
                    socket_fd=sock, option_level="SOL_TCP", option_name="TCP_ULP", option_val="tls_1_2")

                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.dut_addr['device_ip'],
                                                   server_port=local_port, timeout=15)

                logger().info(" ***** DUT is connecting to server socket ***** ")
                connect_status = False
                for count in range(3):
                    try:
                        self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                       server_port=local_port)
                        connect_status = True
                        break
                    except:
                        logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                        time.sleep(10)
                assert connect_status, "Socket connection failed in DUT"
                logger().info(" ***** Socket connection is successful ***** ")

                if self.test_case == 198671:
                    sw = Stopwatch()
                    while sw.elapsed_sec < 30:
                        buffer_length = 100
                        tx_buffer = "".join(choices(string.ascii_uppercase + string.digits, k=buffer_length))

                        logger().info(f"DATA TRANSFER -----DUT SENDING DATA ON SOCKET ID")
                        data_length = len(tx_buffer)
                        self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=tx_buffer)
                        data_receive = self.ssl_server.interfaces.ssl.data_recv_content(socket_no=sock + 1,
                                                                                        buffer_size=data_length)
                        logger().info(f"Data received on remote socket opened is {data_receive}")
                        assert tx_buffer == data_receive.decode(), "Data sent by DUT and received on server is matching"

                if self.test_case == 198672:
                    buffer_length = 50
                    tx_buffer = "".join(choices(string.ascii_uppercase + string.digits, k=buffer_length))
                    pkt_count = 1
                    self.ssl_server.interfaces.ssl.send_data(1, pkt_count, msg_length=50, message=tx_buffer)
                    buffer_rx = self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)

                    assert tx_buffer == buffer_rx, (f"buffer length sent by remote peer and received on the socket id"
                                                    f" {sock} opened in the DUT is not matched ")

                logger().info(f" ***************** Closing Socket From DUT Side **************** ")
                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                self.ssl_server.interfaces.ssl.stop_server()

            if self.test_case == "198663":
                logger().info("Initiating ping from Raspi to DUT to check stability")
                status = ping(self.dut_addr['device_ip'], 30, size=300)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

            if self.test_case == "198669":
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol)
                logger().info(f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}")
                logger().info(f"***** starting iperf ******")
                self.net_perf_client.interfaces.net_perf.start()
                logger().info(f"***** send traffic  ******")
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                                    local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=self.host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    size=1460, ttl=30, throughput_type=2)
                logger().info("data transfer is successful")
                time.sleep(3)

            if self.test_case == 198673 or self.test_case == 198674:
                self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                logger().info("fetching server ip....")
                host_ip = self.http_server.interfaces.http.hostname_or_ip_address
                logger().info(f"http_server_ip: {host_ip}")

                logger().info("pinging to http_server_ip....")
                status = ping(host_ip, self.ping_count)
                assert status, "unable to ping to http_server, please check testline connection and interface in harness"

                status = ""
                for retry in range(0, 3):
                    try:
                        logger().info("checking weather server is running....")
                        server_stat = self.http_server.interfaces.http.started
                        if not server_stat:
                            self.http_server.interfaces.http.start_server()
                        logger().info(f'http server state is {self.http_server.interfaces.http.started}')

                        tcp_socket_id = self.wifi_dut.interfaces.wifi.socket()
                        logger().info(f"Socket open successfully : {tcp_socket_id}")
                        logger().info(
                            f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
                        bind_response = self.wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id,
                                                                           device_ip=self.device_ip,
                                                                           server_port=5001, timeout=5)

                        logger().info(f"Bind socket successfully: {bind_response}")
                        time.sleep(5)
                        logger().info("DUT is connecting to server socket")
                        self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=host_ip,
                                                                       server_port=self.http_server.interfaces.http.port)
                        time.sleep(5)
                        self.wifi_dut.interfaces.wifi.http_client_download(socket_id=tcp_socket_id,
                                                                           file_name=self.index_path,
                                                                           ip_address=host_ip,
                                                                           mode=0, timeout=300)
                        status = True
                        break
                    except Exception as e:
                        logger().info(f"Http download failed {e} retrying for 3 times")
                        self.http_server.interfaces.http.stop_server()
                        status = False
                    assert status, f"Http download failed after 3 times"

                    logger().info(f"Http download is successful")
                    self.http_server.interfaces.http.stop_server()

        except Exception as Ex:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)

    def sniffer_validation(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="association_request")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address, da_addr=self.dut_addr['dut_mac_address'], filter_name="association_response")

        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], filter_name="probe_request")

        logger().info(f"***** Validating association_request packets ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find association_request packets"

        logger().info(f"***** Validating association_response packets ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "Unable to find association_response packets"

        logger().info(f"***** Validating probe_request packets ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find probe_request packets"

    def __print_throughput(self):
        if self.iperf_throughput is not None:
            print_dict("##     ", self.iperf_throughput)


class BleThreadFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_test_type=None, sl_collections=None, test_case=None,
                 ble_dut=None, ble_pairing=0, switch=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_client_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.ble_pairing = ble_pairing
        self.switch = switch

    def run(self):
        """ *************************** Set up DUT for BLE advertising ***************************** """
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.ble_pairing)
        assert (self.ble_dut_address is not None), "Unable to fetch bluetooth address from DUT"
        logger().info(f" BLE DUT ADDRESS : {self.ble_dut_address}")
        time.sleep(5)

        if self.test_case == "198664":
            self.sl_collections.ble_connection(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                               ble_dut_address=self.ble_dut_address, mode="slave", timeout=20)
            self.ble_client.interfaces.bluetooth.hci_tool_manager.update_conn(dev_addr=self.ble_dut_address,
                                                                              min_conn_interval=36,
                                                                              max_conn_interval=36,
                                                                              conn_latency=0, supervision_timeout=3200)
            logger().info(f'wait for 60 seconds to check ble connection stability')
            time.sleep(60)
            self.wifi_dut.interfaces.wifi.ble_get_device_state()

        if self.test_case == 198670 or self.test_case == 198671 or self.test_case == 198662:
            self.sl_collections.ble_connection(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address, timeout=20,
                mode='master')

        if self.test_case == 198669 or self.test_case == 198674 or self.test_case == 198673 or self.test_case == 198672 or self.test_case == 198665 or self.test_case == 198667:
            service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
            char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
            self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
            self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F)
            logger().info(f"Advertising the DUT")
            if self.test_case == 198669 or self.test_case == 198674 or self.test_case == 198672 or self.test_case == 198665:
                self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)
                self.sl_collections.scan_and_connect_from_remote(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                                                 ble_dut_address=self.ble_dut_address,
                                                                 ble_pairing=self.ble_pairing)
            if self.test_case == 198673 or self.test_case == 198667:
                self.sl_collections.ble_connection(
                    wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
                    timeout=20, mode='master')
            servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            assert len(servs) > 0, "no services fetched"
            assert len(chars) > 0, "fetched characters are empty"

            char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=service_uid, char_uid=char_uid)
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"

            self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            logger().info("********* Subscribing to Notifications **********")
            self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path, char_uid=char_uid)
            if self.test_case == 198669 or self.test_case == 198674 or self.test_case == 198673 or self.test_case == 198672 or self.test_case == 198667:
                data = "testwentybytesofdata"
                sw = Stopwatch()
                while sw.elapsed_sec < 60:
                    self.wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data)
                    time.sleep(5)
            if self.test_case == 198665:
                sw = Stopwatch()
                data = "testwentybytesofdata"
                check_flag = False
                while sw.elapsed_sec < 120:
                    logger().info("DUT publishes message over the topic")
                    self.wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data)
                    time.sleep(2)
                    while sw.elapsed_sec < 30:
                        logger().info("DUT publishes message over the topic")
                        self.wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data)
                        time.sleep(2)
                    if check_flag is not True:
                        logger().info('***** Turn off Access point *****')
                        self.switch.interfaces.pdu_switch.turn_off(delay=20)

                        logger().info('******* Turn on Access point **********')
                        self.switch.interfaces.pdu_switch.turn_on(delay=60)
                        check_flag = True
            logger().info("======= get connection state")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"

            logger().info("********* Unsubscribing to Notifications **********")
            self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)

        if self.test_case == "198668":
            logger().info(f"Advertising the DUT")
            self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)
            self.sl_collections.scan_and_connect_from_remote(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                                             ble_dut_address=self.ble_dut_address,
                                                             ble_pairing=self.ble_pairing)

        if self.test_case == 198663:
            self.sl_collections.check_ble_advertise_functionality(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address, timeout=20)
            self.ble_client.interfaces.bluetooth.close()
            time.sleep(3)
            self.sl_collections.check_ble_scan_functionality(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_address=self.ble_dut_address, timeout=20)
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            time.sleep(2)

    def ble_disconnect(self, disconnect_from="remote"):
        self.sl_collections.ble_disconnect(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                           ble_dut_address=self.ble_dut_address,
                                           disconnect_from=disconnect_from, ble_client_address=self.ble_client_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_wlan_connect_11ax_ble_connect_with_diff_int_c198664(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, wifi_client, sniffer_filter):
    """Verify the WLAN connection with 11ax mode and BLE Connection as Slave using different BLE connection intervals"""

    try:
        test_name = request.node.name
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         test_case="198664")

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                           sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        wifi_obj.ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"******** AP MAC ADDRESS {wifi_obj.ap_mac_address} *******")
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        wifi_obj.dut_addr = sl_collections.join_to_wifi_network(
            wifi_dut, wifi_access_point, ping_after_power_save=True, associated=wifi_dut.interfaces.wifi.associated)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")
        ble_obj.ble_disconnect()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [('0xc8', 0)])
def test_wifi_sdk_wlan_tcp_rx_with_11ax_ble_connect_slave_smp_enable_c198668(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, protocol, net_perf_client, traffic, qos):
    """Verify the WLAN TCP Rx data transfer with 11ax AP when BLE Connection as Slave with SMP Enabled"""

    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=1, test_case="198668")

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, qos=qos,
                                           sniffer_filter=sniffer_filter, wifi_client=wifi_client, traffic=traffic,
                                           protocol=protocol, net_perf_client=net_perf_client, test_case="198668")

        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")
        ble_client.interfaces.bluetooth.close()
        ble_obj.ble_disconnect()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos", [('0xc8', 0)])
def test_wifi_sdk_wlan_udp_rx_with_11ax_ble_connect_master_c198670(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, protocol, net_perf_client, traffic, qos):
    """ Verify the WLAN UDP Rx data transfer with 11ax AP when BLE Connection as Master """

    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, test_case=198670)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, qos=qos,
                                           sniffer_filter=sniffer_filter, wifi_client=wifi_client, traffic=traffic,
                                           protocol=protocol, net_perf_client=net_perf_client, test_case="198670")

        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")
        ble_obj.ble_disconnect()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_wlan_ssl_tx_with_11ax_ble_connect_master_c198671(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, ssl_server):
    """ Verify the WLAN SSL Tx data transfer with 11ax AP when BLE Connection as Master """

    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, test_case=198671)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           ssl_server=ssl_server,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                           sniffer_filter=sniffer_filter, wifi_client=wifi_client, test_case=198671)

        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

        ble_obj.ble_disconnect()
        wifi_obj.sniffer_validation()
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [('0xc8', 0)])
def test_wifi_sdk_wlan_tcp_rx_with_11ax_ble_connect_and_disconnect_slave_c198678(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, protocol, net_perf_client, traffic, qos):
    """ Verify the WLAN TCP Tx data transfer with 11ax AP when BLE as Slave Connection and disconnection """

    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=0, test_case="198668")

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, qos=qos,
                                           sniffer_filter=sniffer_filter, wifi_client=wifi_client, traffic=traffic,
                                           protocol=protocol, net_perf_client=net_perf_client, test_case="198678")
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_wlan_connection_with_11ax_ble_slave_c198661(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut):
    """ Verify the WLAN Connection with 11ax AP when BLE idle connection as Slave """

    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=0, test_case="198668")

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                           sniffer_filter=sniffer_filter, wifi_client=wifi_client)
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_wlan_connection_with_11ax_ble_master_c198662(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut):
    """ Verify the WLAN Connection with 11ax AP when BLE idle connection as Master """

    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=0, test_case=198662)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                           sniffer_filter=sniffer_filter, wifi_client=wifi_client)
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_wlan_connection_with_11ax_ping_traffic_ble_master_c198663(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut):
    """ Verify the WLAN Connection with 11ax AP and Ping traffic with BLE Continuous scan and Advertisement Enabled """

    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=0, test_case=198663)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                           sniffer_filter=sniffer_filter, wifi_client=wifi_client, test_case="198663")
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos", [('0xc8', 0)])
def test_wifi_sdk_wlan_udp_tx_with_11ax_ble_connect_slave_notification_c198669(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, protocol, net_perf_client, traffic, qos):
    """ Verify the WLAN UDP Tx data transfer with 11ax AP when BLE Connection as Slave and BLE Notifications enabled """

    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, test_case=198669)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, qos=qos,
                                           sniffer_filter=sniffer_filter, wifi_client=wifi_client, traffic=traffic,
                                           protocol=protocol, net_perf_client=net_perf_client, test_case="198669")

        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")
        ble_obj.ble_disconnect()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_http_download_with_11ax_ble_connect_slave_notification_c198674(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, http_server, index_path, utf_constants):
    """ Verify the HTTP download with 11ax AP when BLE connection as Slave and BLE Notifications enabled """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, test_case=198674)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                           sniffer_filter=sniffer_filter, wifi_client=wifi_client, ping_count=ping_count,
                                           http_server=http_server, index_path=index_path, test_case=198674)

        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")
        ble_obj.ble_disconnect()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
#         "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
#                               | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
#         "custom_features": Si91xCustomFeatureBitMap.Default,
#         "bt_features": Si91xBTFeatureBitMap.Default,
#         "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
#         "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
#     }
# )
# @pytest.mark.http_server("raspi_lighttpd")
# @pytest.mark.parametrize("index_path", {"1MB.htm"})
# @pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
# @pytest.mark.config('wifi_access_point',
#                     wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
# def test_wifi_sdk_http_download_with_11ax_ble_connect_master_notification_c198673(
#         wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
#         ble_dut, http_server, index_path, utf_constants):
#     """ Verify the HTTP download with 11ax AP when BLE connection as Master and BLE Notifications enabled """
#
#     try:
#         test_name = request.node.name
#         ping_count = utf_constants.get("ping_count")
#         logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
#
#         ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
#                                          ble_dut=ble_dut, test_case=198673)
#
#         wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
#                                            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
#                                            sniffer_filter=sniffer_filter, wifi_client=wifi_client, ping_count=ping_count,
#                                            http_server=http_server, index_path=index_path, test_case=198673)
#
#         ble_obj.start()
#         wifi_obj.start()
#         wifi_obj.wait_for_exit()
#         ble_obj.wait_for_exit()
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger().info("Stop the Sniffer")
#         ble_obj.ble_disconnect()
#
#     except Exception as Ex:
#         sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
#
#     finally:
#         ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_wlan_ssl_rx_with_11ax_ble_connect_slave_and_notification_enable_c198672(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, ssl_server):
    """ Verify the WLAN SSL Rx data transfer with 11ax AP when BLE Connection as Slave and BLE Notifications enabled """

    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, test_case=198672)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           ssl_server=ssl_server, wifi_sniffer=wifi_sniffer,
                                           sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                           wifi_client=wifi_client, test_case=198672)

        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
#         "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
#                               | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
#         "custom_features": Si91xCustomFeatureBitMap.Default,
#         "bt_features": Si91xBTFeatureBitMap.Default,
#         "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
#         "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
#     }
# )
# @pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
# @pytest.mark.config('wifi_access_point',
#                     wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP])
# @pytest.mark.parametrize("traffic, qos", [('0xc8', 0)])
# def test_wifi_sdk_wlan_tcp_tx_with_11ax_ble_connect_master_notification_c198667(
#         wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
#         ble_dut, protocol, net_perf_client, traffic, qos):
#     """ Verify the WLAN TCP Tx data transfer with 11ax AP when BLE Connection as Master and BLE Notifications """
#
#     try:
#         test_name = request.node.name
#
#         logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
#
#         ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
#                                          ble_dut=ble_dut, test_case=198667)
#
#         wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
#                                            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, qos=qos,
#                                            sniffer_filter=sniffer_filter, wifi_client=wifi_client, traffic=traffic,
#                                            protocol=protocol, net_perf_client=net_perf_client, test_case="198667")
#
#         ble_obj.start()
#         wifi_obj.start()
#         wifi_obj.wait_for_exit()
#         ble_obj.wait_for_exit()
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger().info("Stop the Sniffer")
#         ble_obj.ble_disconnect()
#         wifi_obj.sniffer_validation()
#
#     except Exception as Ex:
#         sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
#
#     finally:
#         ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_rejoin_11ax_ble_connect_slave_and_notification_enable_c198665(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, switch):
    """Verify the Rejoin functionality with 11ax Connection with BLE Connection as Slave and BLE Notifications"""

    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, test_case=198665, switch=switch)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                           sniffer_filter=sniffer_filter, wifi_client=wifi_client)

        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.sniffer_validation()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        ble_client.interfaces.bluetooth.close()
